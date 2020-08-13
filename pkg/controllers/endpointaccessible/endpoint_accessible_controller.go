package endpointaccessible

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

type endpointAccessibleController struct {
	operatorClient         v1helpers.OperatorClient
	endpointListFn         EndpointListFunc
	availableConditionName string
}

type EndpointListFunc func() ([]string, error)

// NewEndpointAccessibleController returns a controller that checks if the endpoints
// listed by endpointListFn are reachable
func NewEndpointAccessibleController(
	name string,
	operatorClient v1helpers.OperatorClient,
	endpointListFn EndpointListFunc,
	triggers []factory.Informer,
	recorder events.Recorder,
) factory.Controller {
	c := &endpointAccessibleController{
		operatorClient:         operatorClient,
		endpointListFn:         endpointListFn,
		availableConditionName: name + "EndpointAccessibleControllerAvailable",
	}

	return factory.New().
		WithInformers(triggers...).
		WithInformers(operatorClient.Informer()).
		WithSync(c.sync).
		ResyncEvery(30*time.Second).
		WithSyncDegradedOnError(operatorClient).
		ToController(name+"EndpointAccessibleController", recorder.WithComponentSuffix(name+"endpoint-accessible-controller"))
}

func (c *endpointAccessibleController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	endpoints, err := c.endpointListFn()
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

			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				errCh <- err
				return
			}
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // avoid waiting forever
			defer cancel()
			req.WithContext(reqCtx)

			// we don't really care  if anyone lies to us. We aren't sending important data.
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			resp, err := client.Do(req)
			if err != nil {
				errCh <- err
				return
			}

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
	if len(errors) < len(endpoints) {
		if _, _, err := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:   c.availableConditionName,
			Status: operatorv1.ConditionTrue,
			Reason: "AsExpected",
		})); err != nil {
			// append the error to be degraded
			errors = append(errors, err)
		}
	} else {
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

func toHealthzURL(urls []string) []string {
	var res []string
	for _, url := range urls {
		res = append(res, "https://"+url+"/healthz")
	}
	return res
}
