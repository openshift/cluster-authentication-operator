package proxyconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	v1 "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"
)

// proxyConfigChecker reports bad proxy configurations.
type proxyConfigChecker struct {
	routeLister     v1.RouteLister
	configMapLister corev1lister.ConfigMapLister
	routeName       string
	routeNamespace  string
	caConfigMaps    map[string][]string // ns -> []configmapNames

	authConfigChecker common.AuthConfigChecker
}

func NewProxyConfigChecker(
	routeInformer routeinformer.RouteInformer,
	configMapInformers v1helpers.KubeInformersForNamespaces,
	authConfigChecker common.AuthConfigChecker,
	routeNamespace string,
	routeName string,
	caConfigMaps map[string][]string,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClient) factory.Controller {
	p := proxyConfigChecker{
		routeLister:       routeInformer.Lister(),
		configMapLister:   configMapInformers.ConfigMapLister(),
		routeName:         routeName,
		routeNamespace:    routeNamespace,
		caConfigMaps:      caConfigMaps,
		authConfigChecker: authConfigChecker,
	}

	c := factory.New().
		WithSync(p.sync).
		WithInformers(
			routeInformer.Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		ResyncEvery(60 * time.Minute).
		WithSyncDegradedOnError(operatorClient)

	for ns, configMapNames := range caConfigMaps {
		c.WithFilteredEventsInformers(
			factory.NamesFilter(configMapNames...),
			configMapInformers.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
		)
	}

	return c.ToController("ProxyConfigController", recorder.WithComponentSuffix("proxy-config-controller"))
}

// sync attempts to connect to route using configured proxy settings and reports any error.
func (p *proxyConfigChecker) sync(ctx context.Context, _ factory.SyncContext) error {
	if oidcAvailable, err := p.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		return nil
	}

	proxyConfig := httpproxy.FromEnvironment()
	if !isProxyConfigured(proxyConfig) {
		// If proxy is not configured, then it is a no-op.
		return nil
	}

	route, err := p.routeLister.Routes(p.routeNamespace).Get(p.routeName)
	if err != nil {
		return err
	}

	routeURL, _, err := routeapihelpers.IngressURI(route, "")
	if err != nil {
		return err
	}
	routeURL.Path = "healthz"

	clientWithProxy, clientWithoutProxy, err := p.createHTTPClients()
	if err != nil {
		return err
	}

	return checkProxyConfig(ctx, routeURL, proxyConfig.NoProxy, clientWithProxy, clientWithoutProxy)
}

// checkProxyConfig determines any mis-configuration in proxy settings by attempting
// to connect to endpoint directly and via proxy and comparing the results with expectations.
func checkProxyConfig(ctx context.Context, endpointURL *url.URL, noProxy string, clientWithProxy, clientWithoutProxy *http.Client) error {
	withProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithProxy) })
	withoutProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithoutProxy) })
	noProxyMatchesEndpoint := parseNoProxy(noProxy).matches(canonicalAddr(endpointURL))

	if noProxyMatchesEndpoint && withoutProxy() != nil {
		if withProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %v", endpointURL.String(), noProxy, withoutProxy())
		}
		return fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%v) and without proxy(%v)", endpointURL.String(), noProxy, withProxy(), withoutProxy())
	}

	if !noProxyMatchesEndpoint && withProxy() != nil {
		if withoutProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(%q) with error: %v", endpointURL.String(), noProxy, withProxy())
		}
		return fmt.Errorf("endpoint(%q) is unreachable with proxy(%v) and without proxy(%v)", endpointURL.String(), withProxy(), withoutProxy())
	}

	return nil
}

// createHTTPClients returns two http clients, one with proxy and another without proxy
func (p *proxyConfigChecker) createHTTPClients() (*http.Client, *http.Client, error) {
	caPool, err := p.getCACerts()
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs: caPool,
	}

	return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           proxyFunc,
			},
		}, &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}, nil
}

// getCACerts retrieves the CA bundle in openshift cluster
func (p *proxyConfigChecker) getCACerts() (*x509.CertPool, error) {
	caPool := x509.NewCertPool()

	for ns, configMaps := range p.caConfigMaps {
		for _, cmName := range configMaps {
			caCM, err := p.configMapLister.ConfigMaps(ns).Get(cmName)
			if err != nil {
				return nil, err
			}

			// In case this causes performance issues, consider caching the trusted
			// certs pool.
			// At the time of writing this comment, this should only happen once
			// every 5 minutes and the trusted-ca CM contains around 130 certs.
			if ok := caPool.AppendCertsFromPEM([]byte(caCM.Data["ca-bundle.crt"])); !ok {
				return nil, fmt.Errorf("unable to append system trust ca bundle")
			}
		}
	}

	return caPool, nil
}

// isEndpointReachable returns nil if the given endpoint can be reached using the given client
func isEndpointReachable(ctx context.Context, endpointURL string, client *http.Client) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second) // avoid waiting forever
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%q returned %d", endpointURL, resp.StatusCode)
	}
	return nil
}

func isProxyConfigured(proxyConfig *httpproxy.Config) bool {
	return proxyConfig != nil && (len(proxyConfig.HTTPProxy) != 0 || len(proxyConfig.HTTPSProxy) != 0)
}

// proxyFunc returns the proxy URL to be used for a given request
// when NO_PROXY is ignored.
func proxyFunc(req *http.Request) (*url.URL, error) {
	proxyConfig := httpproxy.FromEnvironment()
	if req.URL.Scheme == "https" && len(proxyConfig.HTTPSProxy) > 0 {
		proxyURL, err := url.Parse(proxyConfig.HTTPSProxy)
		if err == nil {
			return proxyURL, nil
		}
		klog.V(4).Infof("failed to parse https proxy %q", proxyConfig.HTTPSProxy)
	}

	proxyURL, err := url.Parse(proxyConfig.HTTPProxy)
	if err != nil {
		return nil, err
	}
	return proxyURL, nil
}

// newLazyChecker returns a function that calculates an error value once
// and returns that error in subsequent calls
func newLazyChecker(f func() error) func() error {
	var err error
	var once sync.Once
	return func() error {
		once.Do(func() {
			err = f()
		})
		return err
	}
}
