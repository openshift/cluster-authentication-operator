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
)

type endpointAccessibleController struct {
	name           string
	operatorClient v1helpers.OperatorClient
	endpointListFn EndpointListFunc
	getTLSConfigFn EndpointTLSConfigFunc
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
	c := &endpointAccessibleController{
		name:           name,
		operatorClient: operatorClient,
		endpointListFn: endpointListFn,
		getTLSConfigFn: getTLSConfigFn,
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

			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				errCh <- err
				return
			}
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // avoid waiting forever
			defer cancel()
			req.WithContext(reqCtx)

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

	return utilerrors.NewAggregate(errors)
}

func (c *endpointAccessibleController) buildTLSClient() (*http.Client, error) {
	transport := &http.Transport{
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
	return &http.Client{Transport: transport}, nil
}
