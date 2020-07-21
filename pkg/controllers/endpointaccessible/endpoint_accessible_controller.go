package endpointaccessible

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type endpointAccessibleController struct {
	endpointsGetter corev1client.EndpointsGetter
	podsGetter      corev1client.PodsGetter
	targetNamespace string
	operatorClient  v1helpers.OperatorClient

	endpointListFn EndpointListFunc
}

type EndpointListFunc func() ([]string, error)

// call this..
// 1. Route with an endpoint based on route.status.host.  If missing, this should return an error
// 2. Service with an endpoint based on the service IP.  If missing, this should return an error
// 3. Endpoint with an based on the endpoints resources.  If missing, this should return an error.
func NewEndpointAccessibleController(
	name string, // CamelCase
	operatorClient v1helpers.OperatorClient,
	endpointListFn EndpointListFunc, // will be called a lot.  use caches.
	triggers []factory.Informer, // anything that impacts the values for endpointListFn should be here
	recorder events.Recorder,
) factory.Controller {
	c := &endpointAccessibleController{
		operatorClient: operatorClient,
		endpointListFn: endpointListFn,
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
		go func() {
			defer wg.Done()

			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				errCh <- err
				return
			}
			reqCtx, _ := context.WithTimeout(ctx, 10*time.Second) // avoid waiting forever
			req.WithContext(reqCtx)

			// we don't really care  if anyone lies to us. We aren't sending important data.
			insecureTransport := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: insecureTransport}

			resp, err := client.Do(req)
			if err != nil {
				errCh <- err
				return
			}
			if resp.StatusCode > 299 || resp.StatusCode < 200 {
				errCh <- fmt.Errorf("%q returned %q", endpoint, resp.Status)
			}
		}()
	}
	wg.Done()

	errors := []error{}
	for err := range errCh {
		errors = append(errors, err)
	}

	return utilerrors.NewAggregate(errors)
}
