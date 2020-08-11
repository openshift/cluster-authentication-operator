package endpointaccessible

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	routev1informers "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// NewOAuthRouteCheckController returns a controller that checks the health of authentication route.
func NewOAuthRouteCheckController(
	operatorClient v1helpers.OperatorClient,
	routeInformerNamespaces routev1informers.RouteInformer,
	recorder events.Recorder,
) factory.Controller {
	routeLister := routeInformerNamespaces.Lister()
	routeInformer := routeInformerNamespaces.Informer()
	endpointListFunc := func() ([]string, error) {
		return listOAuthRoutes(routeLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthRouteCheck",
		operatorClient, endpointListFunc, []factory.Informer{routeInformer}, recorder)
}

// NewOAuthServiceCheckController returns a controller that checks the health of authentication service.
func NewOAuthServiceCheckController(
	operatorClient v1helpers.OperatorClient,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	serviceLister := corev1Informers.Services().Lister()
	serviceInformer := corev1Informers.Services().Informer()
	endpointsListFunc := func() ([]string, error) {
		return listOAuthServices(serviceLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthServiceCheck",
		operatorClient, endpointsListFunc, []factory.Informer{serviceInformer}, recorder)
}

// NewOAuthServiceEndpointsCheckController returns a controller that checks the health of authentication service
// endpoints.
func NewOAuthServiceEndpointsCheckController(
	operatorClient v1helpers.OperatorClient,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	endpointsLister := corev1Informers.Endpoints().Lister()
	endpointsInformer := corev1Informers.Endpoints().Informer()

	endpointsListFn := func() ([]string, error) {
		return listOAuthServiceEndpoints(endpointsLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthServiceEndpointsCheck",
		operatorClient, endpointsListFn, []factory.Informer{endpointsInformer}, recorder)
}

func listOAuthServiceEndpoints(endpointsLister corev1listers.EndpointsLister, recorder events.Recorder) ([]string, error) {
	var results []string
	endpoints, err := endpointsLister.Endpoints("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthServiceEndpointsCheck", "failed to get oauth service endpoints: %v", err)
		return results, nil
	}
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			for _, port := range subset.Ports {
				results = append(results, net.JoinHostPort(address.IP, strconv.Itoa(int(port.Port))))
			}
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("oauth service endpoints are not ready")
	}
	return toHealthzURL(results), nil
}

func listOAuthServices(serviceLister corev1listers.ServiceLister, recorder events.Recorder) ([]string, error) {
	var results []string
	service, err := serviceLister.Services("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthServiceCheck", "failed to get oauth service: %v", err)
		return nil, err
	}
	for _, port := range service.Spec.Ports {
		results = append(results, net.JoinHostPort(service.Spec.ClusterIP, strconv.Itoa(int(port.Port))))
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no valid oauth services found")
	}
	return toHealthzURL(results), nil
}

func listOAuthRoutes(routeLister routev1listers.RouteLister, recorder events.Recorder) ([]string, error) {
	var results []string
	route, err := routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthRouteCheck", "failed to get oauth route: %v", err)
		return nil, err
	}
	for _, ingress := range route.Status.Ingress {
		if len(ingress.Host) > 0 {
			results = append(results, ingress.Host)
		}
	}
	if len(results) == 0 {
		recorder.Warningf("OAuthRouteCheck", "route status does not have host address")
		return nil, fmt.Errorf("route status does not have host address")
	}
	return toHealthzURL(results), nil
}

type endpointAccessibleController struct {
	operatorClient v1helpers.OperatorClient
	endpointListFn EndpointListFunc
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

	return utilerrors.NewAggregate(errors)
}

func toHealthzURL(urls []string) []string {
	var res []string
	for _, url := range urls {
		res = append(res, "https://"+url+"/healthz")
	}
	return res
}
