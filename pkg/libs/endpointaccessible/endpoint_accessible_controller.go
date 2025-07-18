package endpointaccessible

import (
	"context"
	"crypto/tls"
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

type endpointAccessibleController struct {
	controllerInstanceName    string
	operatorClient            v1helpers.OperatorClient
	endpointListFn            EndpointListFunc
	getTLSConfigFn            EndpointTLSConfigFunc
	availableConditionName    string
	endpointCheckDisabledFunc EndpointCheckDisabledFunc
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
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
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

	endpoints, err := c.endpointListFn()
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

		return err
	}

	client, err := c.buildTLSClient()
	if err != nil {
		return err
	}
	// check all the endpoints in parallel.  This matters for pods.
	errCh := make(chan error, len(endpoints))
	wg := sync.WaitGroup{}
	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()

			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // avoid waiting forever
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
			defer resp.Body.Close()

			if resp.StatusCode > 299 || resp.StatusCode < 200 {
				errCh <- fmt.Errorf("%q returned %q", endpoint, resp.Status)
			}
		}(endpoint)
	}
	wg.Wait()
	close(errCh)

	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	// if at least one endpoint responded, we are available
	if len(endpoints) > 0 && len(errors) < len(endpoints) {
		status := applyoperatorv1.OperatorStatus().
			WithConditions(applyoperatorv1.OperatorCondition().
				WithType(c.availableConditionName).
				WithStatus(operatorv1.ConditionTrue).
				WithReason("AsExpected"))
		if err := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); err != nil {
			// append the error to be degraded
			errors = append(errors, err)
		}
	} else {
		// in case there are no endpoints returned, go available=false
		if len(endpoints) == 0 {
			errors = append(errors, fmt.Errorf("failed to get oauth-openshift endpoints"))
		}
		status := applyoperatorv1.OperatorStatus().
			WithConditions(applyoperatorv1.OperatorCondition().
				WithType(c.availableConditionName).
				WithStatus(operatorv1.ConditionFalse).
				WithReason("EndpointUnavailable").
				WithMessage(utilerrors.NewAggregate(errors).Error()))
		if err := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); err != nil {
			// append the error to be degraded
			errors = append(errors, err)
		}
	}

	return utilerrors.NewAggregate(errors)
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
		Timeout:   5 * time.Second,
		Transport: transport,
	}, nil
}
