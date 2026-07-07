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

	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	v1 "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

// proxyConfigChecker reports bad proxy configurations.
type proxyConfigChecker struct {
	routeLister     v1.RouteLister
	configMapLister corev1lister.ConfigMapLister
	routeName       string
	routeNamespace  string
	caConfigMaps    map[string][]string // ns -> []configmapNames

	oauthLister   configv1listers.OAuthLister
	proxyResolver common.ProxyResolver

	authConfigChecker common.AuthConfigChecker

	lastIdPValidationHash string
}

func NewProxyConfigChecker(
	routeInformer routeinformer.RouteInformer,
	configMapInformers v1helpers.KubeInformersForNamespaces,
	authConfigChecker common.AuthConfigChecker,
	routeNamespace string,
	routeName string,
	caConfigMaps map[string][]string,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClient,
	oauthLister configv1listers.OAuthLister,
	proxyResolver *common.AuthProxyResolver,
) factory.Controller {
	p := proxyConfigChecker{
		routeLister:       routeInformer.Lister(),
		configMapLister:   configMapInformers.ConfigMapLister(),
		routeName:         routeName,
		routeNamespace:    routeNamespace,
		caConfigMaps:      caConfigMaps,
		oauthLister:       oauthLister,
		proxyResolver:     proxyResolver,
		authConfigChecker: authConfigChecker,
	}

	c := factory.New().
		WithSync(p.sync).
		WithInformers(
			routeInformer.Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		WithInformers(proxyResolver.Informer()).
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

// sync attempts to connect to the route using the active proxy settings and reports
// any misconfiguration. ResolveProxy returns effective proxy settings for both
// cluster-wide and component-scoped proxies, so the validation logic is the same.
func (p *proxyConfigChecker) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := p.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		return nil
	}

	proxy, err := p.proxyResolver.ResolveProxy()
	if err != nil {
		return err
	}
	if !proxy.IsProxyConfigured() {
		return nil
	}

	routeURL, err := p.getRouteHealthzURL()
	if err != nil {
		return err
	}

	clientWithProxy, clientWithoutProxy, err := p.createHTTPClients()
	if err != nil {
		return err
	}

	if err := checkProxyConfig(ctx, routeURL, proxy.NoProxy, clientWithProxy, clientWithoutProxy); err != nil {
		return err
	}

	p.validateIdPConnectivity(ctx, syncCtx.Recorder(), clientWithProxy, proxy.HTTPProxy, proxy.HTTPSProxy, proxy.NoProxy)
	return nil
}

// validateIdPConnectivity tests that configured IdP endpoints are reachable through
// the proxy. Only runs on config change (tracked by hash). Reports warnings
// for transient IdP failures instead of returning errors (which would set Degraded),
// since external IdPs can be unreachable for reasons unrelated to proxy configuration.
func (p *proxyConfigChecker) validateIdPConnectivity(ctx context.Context, recorder events.Recorder, client *http.Client, httpProxy, httpsProxy, noProxy string) {
	oauthConfig, err := p.oauthLister.Get("cluster")
	if err != nil {
		klog.Warningf("unable to get oauth config for IdP validation: %v", err)
		return
	}

	idpURLs := extractIdPURLs(oauthConfig)
	if len(idpURLs) == 0 {
		return
	}

	hash := computeIdPValidationHash(httpProxy, httpsProxy, noProxy, idpURLs)
	if hash == p.lastIdPValidationHash {
		return
	}

	var unreachable []string
	for _, idpURL := range idpURLs {
		if err := isEndpointReachable(ctx, idpURL, client); err != nil {
			klog.Warningf("IdP endpoint unreachable through proxy: %v", err)
			unreachable = append(unreachable, err.Error())
		}
	}
	if len(unreachable) > 0 {
		recorder.Warningf("IdPEndpointUnreachable", "IdP endpoints unreachable through proxy: %s", strings.Join(unreachable, "; "))
	} else {
		p.lastIdPValidationHash = hash
	}
}

// extractIdPURLs returns external URLs from configured identity providers.
func extractIdPURLs(oauthConfig *configv1.OAuth) []string {
	var urls []string
	for _, idp := range oauthConfig.Spec.IdentityProviders {
		switch {
		case idp.OpenID != nil && len(idp.OpenID.Issuer) > 0:
			issuer := strings.TrimSuffix(idp.OpenID.Issuer, "/")
			urls = append(urls, issuer+"/.well-known/openid-configuration")
		case idp.GitHub != nil:
			host := idp.GitHub.Hostname
			if len(host) == 0 {
				host = "github.com"
			}
			urls = append(urls, "https://"+host)
		case idp.GitLab != nil && len(idp.GitLab.URL) > 0:
			urls = append(urls, idp.GitLab.URL)
		case idp.Keystone != nil && len(idp.Keystone.URL) > 0:
			urls = append(urls, idp.Keystone.URL)
		case idp.BasicAuth != nil && len(idp.BasicAuth.URL) > 0:
			urls = append(urls, idp.BasicAuth.URL)
		case idp.Google != nil:
			urls = append(urls, "https://accounts.google.com")
		}
	}
	return urls
}

func computeIdPValidationHash(httpProxy, httpsProxy, noProxy string, idpURLs []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", httpProxy, httpsProxy, noProxy)
	for _, u := range idpURLs {
		fmt.Fprintf(h, "%s\n", u)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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

func (p *proxyConfigChecker) getRouteHealthzURL() (*url.URL, error) {
	route, err := p.routeLister.Routes(p.routeNamespace).Get(p.routeName)
	if err != nil {
		return nil, err
	}
	routeURL, _, err := routeapihelpers.IngressURI(route, "")
	if err != nil {
		return nil, err
	}
	routeURL.Path = "healthz"
	return routeURL, nil
}

// createHTTPClients returns two HTTP clients — one that routes through the proxy
// and one that connects directly.
func (p *proxyConfigChecker) createHTTPClients() (*http.Client, *http.Client, error) {
	caPool, err := p.getCAPool()
	if err != nil {
		return nil, nil, err
	}
	poolOpt := common.WithCertPool(caPool)

	withProxy, err := p.proxyResolver.NewTransport(poolOpt)
	if err != nil {
		return nil, nil, err
	}

	withoutProxy, err := p.proxyResolver.NewTransport(poolOpt)
	if err != nil {
		return nil, nil, err
	}
	withoutProxy.Proxy = nil

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
			if ok := pool.AppendCertsFromPEM([]byte(caCM.Data["ca-bundle.crt"])); !ok {
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
