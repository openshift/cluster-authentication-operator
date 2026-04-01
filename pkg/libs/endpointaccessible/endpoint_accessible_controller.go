package endpointaccessible

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// The following constants are put together so that
// all attempts fit safely into resyncInterval.
const (
	resyncInterval = 1 * time.Minute

	defaultRequestTimeout = 5 * time.Second
	defaultRetryInterval  = 2 * time.Second
	defaultAttemptCount   = 3
)

type endpointAccessibleController struct {
	controllerInstanceName    string
	operatorClient            v1helpers.OperatorClient
	endpointListFn            EndpointListFunc
	getTLSConfigFn            EndpointTLSConfigFunc
	availableConditionName    string
	endpointCheckDisabledFunc EndpointCheckDisabledFunc
	// httpClient overrides the default TLS client when set; used in tests.
	httpClient *http.Client
	// requestTimeout is the per-request context timeout.
	// Defaults to defaultRequestTimeout when unset.
	requestTimeout time.Duration
	// retryInterval is the sleep duration between retry attempts.
	// Defaults to defaultRetryInterval when unset.
	retryInterval time.Duration
	// attemptCount is the maximum number of fetch+check cycles.
	// Defaults to defaultAttemptCount when unset.
	attemptCount int
}

type EndpointListFunc func() ([]string, error)
type EndpointTLSConfigFunc func() (*tls.Config, error)
type EndpointCheckDisabledFunc func() (bool, error)

// NewEndpointAccessibleController returns a controller that checks if the endpoints
// listed by endpointListFn are reachable
func NewEndpointAccessibleController(
	name string,
	operatorClient v1helpers.OperatorClient,
	endpointListFn EndpointListFunc,
	getTLSConfigFn EndpointTLSConfigFunc,
	endpointCheckDisabledFunc EndpointCheckDisabledFunc,
	triggers []factory.Informer,
	recorder events.Recorder,
) factory.Controller {
	controllerName := name + "EndpointAccessibleController"

	c := &endpointAccessibleController{
		controllerInstanceName:    factory.ControllerInstanceName(name, "EndpointAccessible"),
		operatorClient:            operatorClient,
		endpointListFn:            endpointListFn,
		getTLSConfigFn:            getTLSConfigFn,
		availableConditionName:    name + "EndpointAccessibleControllerAvailable",
		endpointCheckDisabledFunc: endpointCheckDisabledFunc,
	}

	return factory.New().
		WithInformers(triggers...).
		WithInformers(operatorClient.Informer()).
		WithSync(c.sync).
		ResyncEvery(wait.Jitter(resyncInterval, 1.0)).
		WithSyncDegradedOnError(operatorClient).
		ToController(
			controllerName, // Don't change what is passed here unless you also remove the old FooDegraded condition
			recorder.WithComponentSuffix(name+"endpoint-accessible-controller"))
}

// humanizeError produce error message that makes more sense to humans/admins.
func humanizeError(err error) error {
	switch {
	case strings.Contains(err.Error(), ":53: no such host"):
		return fmt.Errorf("%v (this is likely result of malfunctioning DNS server)", err)
	default:
		return err
	}
}

func (c *endpointAccessibleController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if c.endpointCheckDisabledFunc != nil {
		if skip, err := c.endpointCheckDisabledFunc(); err != nil {
			return err
		} else if skip {
			// Server-Side-Apply with an empty operator status for the specific field manager
			// will effectively remove any conditions owned by it since the list type in the
			// API definition is 'map'
			return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, applyoperatorv1.OperatorStatus())
		}
	}

	client := c.httpClient
	if client == nil {
		var err error
		client, err = c.buildTLSClient()
		if err != nil {
			return err
		}
	}

	// Retry the full fetch+check cycle so that stale pod IPs from a rolling
	// upgrade are replaced with fresh ones as soon as the Endpoints object is
	// updated between attempts.
	var (
		endpoints []string
		errs      []error
	)
	attempts := c.attemptCount
	if attempts <= 0 {
		attempts = defaultAttemptCount
	}
	requestTimeout := c.requestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}
	retryInterval := c.retryInterval
	if retryInterval <= 0 {
		retryInterval = defaultRetryInterval
	}
	prevTimedOut := false
	for i := range attempts {
		// Sleep before the next attempt to give the Endpoints object time to
		// be updated (e.g. during a rolling upgrade). Skip the sleep when the
		// previous attempt timed out — we already waited requestTimeout.
		if i > 0 && !prevTimedOut {
			select {
			case <-time.After(retryInterval):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		prevTimedOut = false

		var err error
		endpoints, err = c.endpointListFn()
		if err != nil {
			if apierrors.IsNotFound(err) {
				status := applyoperatorv1.OperatorStatus().
					WithConditions(applyoperatorv1.OperatorCondition().
						WithType(c.availableConditionName).
						WithStatus(operatorv1.ConditionFalse).
						WithReason("ResourceNotFound").
						WithMessage(err.Error()))
				return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status)
			}
			// Do not retry on endpoint list error since these are not transient.
			return err
		}

		// Check all the endpoints in parallel. This matters for pods.
		errCh := make(chan error, len(endpoints))
		wg := sync.WaitGroup{}
		for _, endpoint := range endpoints {
			wg.Add(1)
			go func(endpoint string) {
				defer wg.Done()

				reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
				defer cancel()

				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
				if err != nil {
					errCh <- humanizeError(err)
					return
				}

				resp, err := client.Do(req)
				if err != nil {
					errCh <- humanizeError(err)
					return
				}
				defer resp.Body.Close() //nolint:errcheck

				if resp.StatusCode > 299 || resp.StatusCode < 200 {
					errCh <- fmt.Errorf("%q returned %q", endpoint, resp.Status)
				}
			}(endpoint)
		}
		wg.Wait()
		close(errCh)

		errs = nil
		for err := range errCh {
			errs = append(errs, err)
			if errors.Is(err, context.DeadlineExceeded) {
				prevTimedOut = true
			}
		}

		if len(endpoints) > 0 && len(errs) < len(endpoints) {
			break // at least one endpoint responded; no need to retry
		}
	}

	// if at least one endpoint responded, we are available
	if len(endpoints) > 0 && len(errs) < len(endpoints) {
		status := applyoperatorv1.OperatorStatus().
			WithConditions(applyoperatorv1.OperatorCondition().
				WithType(c.availableConditionName).
				WithStatus(operatorv1.ConditionTrue).
				WithReason("AsExpected"))
		if err := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); err != nil {
			// append the error to be degraded
			errs = append(errs, err)
		}
	} else {
		// in case there are no endpoints returned, go available=false
		if len(endpoints) == 0 {
			errs = append(errs, fmt.Errorf("failed to get oauth-openshift endpoints"))
		}
		status := applyoperatorv1.OperatorStatus().
			WithConditions(applyoperatorv1.OperatorCondition().
				WithType(c.availableConditionName).
				WithStatus(operatorv1.ConditionFalse).
				WithReason("EndpointUnavailable").
				WithMessage(utilerrors.NewAggregate(errs).Error()))
		if err := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); err != nil {
			// append the error to be degraded
			errs = append(errs, err)
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (c *endpointAccessibleController) buildTLSClient() (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if c.getTLSConfigFn != nil {
		tlsConfig, err := c.getTLSConfigFn()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Transport: transport,
	}, nil
}
