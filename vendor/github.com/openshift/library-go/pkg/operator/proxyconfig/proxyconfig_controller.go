package proxyconfig

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// Option customizes the proxy config controller.
type Option func(*proxyConfigChecker)

// WithPrecondition sets a function that is evaluated at the beginning of every sync.
// When it returns false, the sync is skipped.
func WithPrecondition(precondition func() (bool, error)) Option {
	return func(p *proxyConfigChecker) { p.precondition = precondition }
}

// WithNoProxyCheckedEndpoints sets a function returning endpoints that are probed both with and
// without the proxy. The results are compared with whether NO_PROXY covers the endpoint, and any
// disagreement is returned as a sync error (so the operator goes Degraded).
func WithNoProxyCheckedEndpoints(endpoints func() ([]*url.URL, error)) Option {
	return func(p *proxyConfigChecker) { p.noProxyEndpoints = endpoints }
}

// WithProxiedEndpoints sets a function returning endpoints that are probed through the proxy.
// Failures only emit a warning event with the given reason (they never degrade the operator)
// and the check is skipped until the proxy settings or the endpoints change.
func WithProxiedEndpoints(eventReason string, endpoints func() ([]string, error)) Option {
	return func(p *proxyConfigChecker) {
		p.proxiedEventReason = eventReason
		p.proxiedEndpoints = endpoints
	}
}

// WithInformers adds informers that trigger the controller, typically the sources of the
// callbacks and the informer of the proxy resolver.
func WithInformers(informers ...factory.Informer) Option {
	return func(p *proxyConfigChecker) { p.informers = append(p.informers, informers...) }
}

// proxyConfigChecker reports bad proxy configurations.
type proxyConfigChecker struct {
	configMapLister corev1listers.ConfigMapLister
	caConfigMaps    map[string][]string // ns -> []configmapNames
	proxyResolver   ProxyResolver

	precondition       func() (bool, error)
	noProxyEndpoints   func() ([]*url.URL, error)
	proxiedEventReason string
	proxiedEndpoints   func() ([]string, error)
	informers          []factory.Informer

	lastProxiedValidationHash string
}

// NewProxyConfigController returns a controller validating that proxy settings work.
// instanceName is used as the controller name, and thus determines the Degraded condition type.
func NewProxyConfigController(
	instanceName string,
	proxyResolver ProxyResolver,
	configMapInformers v1helpers.KubeInformersForNamespaces,
	caConfigMaps map[string][]string,
	operatorClient v1helpers.OperatorClient,
	recorder events.Recorder,
	opts ...Option,
) factory.Controller {
	p := &proxyConfigChecker{
		configMapLister: configMapInformers.ConfigMapLister(),
		caConfigMaps:    caConfigMaps,
		proxyResolver:   proxyResolver,
	}
	for _, opt := range opts {
		opt(p)
	}

	c := factory.New().
		WithSync(p.sync).
		WithInformers(p.informers...).
		ResyncEvery(60 * time.Minute).
		WithSyncDegradedOnError(operatorClient)

	for ns, configMapNames := range caConfigMaps {
		c.WithFilteredEventsInformers(
			factory.NamesFilter(configMapNames...),
			configMapInformers.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
		)
	}

	return c.ToController(instanceName+"Controller", recorder.WithComponentSuffix("proxy-config-controller"))
}

// sync attempts to connect to the configured endpoints using the active proxy settings and reports
// any misconfiguration. ResolveProxy returns effective proxy settings for both
// cluster-wide and component-scoped proxies, so the validation logic is the same.
func (p *proxyConfigChecker) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if p.precondition != nil {
		if ok, err := p.precondition(); err != nil {
			return err
		} else if !ok {
			return nil
		}
	}

	proxy, err := p.proxyResolver.ResolveProxy()
	if err != nil {
		return err
	}
	if !proxy.IsProxyConfigured() {
		return nil
	}

	var endpoints []*url.URL
	if p.noProxyEndpoints != nil {
		endpoints, err = p.noProxyEndpoints()
		if err != nil {
			return err
		}
	}

	clientWithProxy, clientWithoutProxy, err := p.createHTTPClients()
	if err != nil {
		return err
	}

	var errs []error
	for _, endpoint := range endpoints {
		if err := checkProxyConfig(ctx, endpoint, strings.Join(proxy.NoProxy, ","), clientWithProxy, clientWithoutProxy); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return utilerrors.NewAggregate(errs)
	}

	if p.proxiedEndpoints != nil {
		p.validateProxiedEndpoints(ctx, syncCtx.Recorder(), clientWithProxy, proxy)
	}
	return nil
}

// validateProxiedEndpoints tests that the endpoints are reachable through the proxy.
// Only runs on config change (tracked by hash). Reports warnings for failures instead
// of returning errors (which would set Degraded), since external endpoints can be
// unreachable for reasons unrelated to proxy configuration.
func (p *proxyConfigChecker) validateProxiedEndpoints(ctx context.Context, recorder events.Recorder, client *http.Client, proxy ResolvedProxy) {
	endpoints, err := p.proxiedEndpoints()
	if err != nil {
		klog.Warningf("unable to get endpoints for proxy validation: %v", err)
		return
	}
	if len(endpoints) == 0 {
		p.lastProxiedValidationHash = ""
		return
	}

	hash := computeValidationHash(proxy.HTTPProxy, proxy.HTTPSProxy, strings.Join(proxy.NoProxy, ","), endpoints)
	if hash == p.lastProxiedValidationHash {
		return
	}

	var unreachable []string
	for _, endpoint := range endpoints {
		if err := isEndpointReachable(ctx, endpoint, client); err != nil {
			klog.Warningf("endpoint unreachable through proxy: %v", err)
			unreachable = append(unreachable, err.Error())
		}
	}
	if len(unreachable) > 0 {
		recorder.Warningf(p.proxiedEventReason, "endpoints unreachable through proxy: %s", strings.Join(unreachable, "; "))
	} else {
		p.lastProxiedValidationHash = hash
	}
}

func computeValidationHash(httpProxy, httpsProxy, noProxy string, endpoints []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", httpProxy, httpsProxy, noProxy)
	for _, u := range endpoints {
		fmt.Fprintf(h, "%s\n", u)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// noProxyMatches returns true if the endpoint is covered by the noProxy setting.
func noProxyMatches(noProxy string, endpointURL *url.URL) bool {
	// With the dummy proxies set, ProxyFunc only returns nil when the endpoint is excluded by NoProxy.
	proxyURL, err := (&httpproxy.Config{HTTPProxy: "dummy", HTTPSProxy: "dummy", NoProxy: noProxy}).ProxyFunc()(endpointURL)
	return err == nil && proxyURL == nil
}

// checkProxyConfig determines any mis-configuration in proxy settings by attempting
// to connect to endpoint directly and via proxy and comparing the results with expectations.
func checkProxyConfig(ctx context.Context, endpointURL *url.URL, noProxy string, clientWithProxy, clientWithoutProxy *http.Client) error {
	withProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithProxy) })
	withoutProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithoutProxy) })
	noProxyMatchesEndpoint := noProxyMatches(noProxy, endpointURL)

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

// createHTTPClients returns two HTTP clients — one that routes through the proxy
// and one that connects directly.
func (p *proxyConfigChecker) createHTTPClients() (*http.Client, *http.Client, error) {
	caPool, err := p.getCAPool()
	if err != nil {
		return nil, nil, err
	}
	poolOpt := httptransport.WithCertPool(caPool)

	withProxy, err := p.proxyResolver.NewTransport(poolOpt)
	if err != nil {
		return nil, nil, err
	}

	withoutProxy, err := p.proxyResolver.NewTransport(poolOpt, httptransport.WithProxyFunc(nil))
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{Transport: withProxy}, &http.Client{Transport: withoutProxy}, nil
}

// getCAPool builds a certificate pool from the configured system trust ConfigMaps.
func (p *proxyConfigChecker) getCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for ns, configMaps := range p.caConfigMaps {
		for _, cmName := range configMaps {
			caCM, err := p.configMapLister.ConfigMaps(ns).Get(cmName)
			if err != nil {
				return nil, err
			}
			if ok := pool.AppendCertsFromPEM([]byte(caCM.Data[trustedCAKey])); !ok {
				return nil, fmt.Errorf("unable to parse CA bundle from configmap %s/%s", ns, cmName)
			}
		}
	}
	return pool, nil
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
