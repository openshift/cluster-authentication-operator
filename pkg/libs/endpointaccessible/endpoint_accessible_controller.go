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
	recorder events.Recorder,
) factory.Controller {
	controllerName := name + "EndpointAccessibleController"

	c := &endpointAccessibleController{
		operatorClient:         operatorClient,
		endpointListFn:         endpointListFn,
		getTLSConfigFn:         getTLSConfigFn,
		availableConditionName: name + "EndpointAccessibleControllerAvailable",
	}

	return factory.New().
		WithInformers(triggers...).
		WithInformers(operatorClient.Informer()).
		WithSync(c.sync).
		ResyncEvery(30*time.Second).
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
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, _, statusErr := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(
				operatorv1.OperatorCondition{
					Type:    c.availableConditionName,
					Status:  operatorv1.ConditionFalse,
					Reason:  "ResourceNotFound",
					Message: err.Error(),
				}))

			return statusErr
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
		if _, _, err := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
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
			errors = append(errors, fmt.Errorf("Failed to get oauth-openshift enpoints"))
		}
		if _, _, err := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
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
