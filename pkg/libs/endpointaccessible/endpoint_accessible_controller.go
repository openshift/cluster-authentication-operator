package endpointaccessible

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type endpointAccessibleController struct {
	operatorClient         v1helpers.OperatorClient
	endpointListFn         EndpointListFunc
	getTLSConfigFn         EndpointTLSConfigFunc
	availableConditionName string

	maxCheckLatency time.Duration
	lastCheckTime   time.Time
	lastEndpoints   sets.Set[string]
	lastServerName  string
	lastCA          *x509.CertPool
}

type EndpointListFunc func() ([]string, error)
type EndpointTLSConfigFunc func() (*tls.Config, error)

// NewEndpointAccessibleController returns a controller that checks if the endpoints
// listed by endpointListFn are reachable
func NewEndpointAccessibleController(
	name string,
	operatorClient v1helpers.OperatorClient,
	endpointListFn EndpointListFunc,
	getTLSConfigFn EndpointTLSConfigFunc,
	triggers []factory.Informer,
	triggersFilterFunc factory.EventFilterFunc,
	recorder events.Recorder,
	resyncInterval time.Duration,
) factory.Controller {
	controllerName := name + "EndpointAccessibleController"

	c := &endpointAccessibleController{
		operatorClient:         operatorClient,
		endpointListFn:         endpointListFn,
		getTLSConfigFn:         getTLSConfigFn,
		availableConditionName: name + "EndpointAccessibleControllerAvailable",
		maxCheckLatency:        resyncInterval - 5*time.Second,
		lastEndpoints:          sets.New[string](),
	}

	return factory.New().
		WithFilteredEventsInformers(triggersFilterFunc, triggers...).
		WithInformers(operatorClient.Informer()).
		WithSync(c.sync).
		ResyncEvery(resyncInterval).
		WithSyncDegradedOnError(operatorClient).
		ToController(controllerName, recorder.WithComponentSuffix(name+"endpoint-accessible-controller"))
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
	endpoints, err := c.endpointListFn()
	if apierrors.IsNotFound(err) {
		_, _, statusErr := v1helpers.UpdateStatus(ctx, c.operatorClient, v1helpers.UpdateConditionFn(
			operatorv1.OperatorCondition{
				Type:    c.availableConditionName,
				Status:  operatorv1.ConditionFalse,
				Reason:  "ResourceNotFound",
				Message: err.Error(),
			}))

		return statusErr
	} else if err != nil {
		return err
	}

	newEndpoints := sets.New(endpoints...)
	endpointsChanged := !c.lastEndpoints.Equal(newEndpoints)

	tlsConfig, err := c.getTLSConfigFn()
	if err != nil {
		return err
	}
	tlsChanged := c.lastServerName != tlsConfig.ServerName || !tlsConfig.RootCAs.Equal(c.lastCA)

	isPastTimeForCheck := time.Since(c.lastCheckTime) > c.maxCheckLatency
	if !endpointsChanged && !tlsChanged && !isPastTimeForCheck {
		return nil
	}
	c.lastCheckTime = time.Now()
	c.lastEndpoints = newEndpoints

	client, err := c.buildTLSClient(tlsConfig)
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
		if _, _, err := v1helpers.UpdateStatus(ctx, c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:   c.availableConditionName,
			Status: operatorv1.ConditionTrue,
			Reason: "AsExpected",
		})); err != nil {
			// append the error to be degraded
			errors = append(errors, err)
		}
	} else {
		// in case there are no endpoints returned, go available=false
		if len(endpoints) == 0 {
			errors = append(errors, fmt.Errorf("failed to get oauth-openshift endpoints"))
		}
		if _, _, err := v1helpers.UpdateStatus(ctx, c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:    c.availableConditionName,
			Status:  operatorv1.ConditionFalse,
			Reason:  "EndpointUnavailable",
			Message: utilerrors.NewAggregate(errors).Error(),
		})); err != nil {
			// append the error to be degraded
			errors = append(errors, err)
		}
	}

	return utilerrors.NewAggregate(errors)
}

func (c *endpointAccessibleController) buildTLSClient(tlsConfig *tls.Config) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig

		// these are the fields that are set by our getTLSConfigFn funcs
		c.lastServerName = tlsConfig.ServerName
		c.lastCA = tlsConfig.RootCAs
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}, nil
}
