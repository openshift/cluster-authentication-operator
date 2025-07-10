package oauthclientscontroller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	oauthv1listers "github.com/openshift/client-go/oauth/listers/oauth/v1"
	routeinformers "github.com/openshift/client-go/route/informers/externalversions"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/customroute"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/oauthclientsswitchedinformer"
)

type oauthsClientsController struct {
	oauthClientClient oauthclient.OAuthClientInterface

	oauthClientInformer cache.SharedIndexInformer
	oauthClientLister   oauthv1listers.OAuthClientLister
	routeLister         routev1listers.RouteLister
	ingressLister       configv1listers.IngressLister

	authConfigChecker common.AuthConfigChecker
}

func NewOAuthClientsController(
	operatorClient v1helpers.OperatorClient,
	oauthsClientClient oauthclient.OAuthClientInterface,
	oauthClientsSwitchedInformer *oauthclientsswitchedinformer.InformerWithSwitch,
	routeInformers routeinformers.SharedInformerFactory,
	operatorConfigInformers configinformers.SharedInformerFactory,
	authConfigChecker common.AuthConfigChecker,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &oauthsClientsController{
		oauthClientClient: oauthsClientClient,

		oauthClientInformer: oauthClientsSwitchedInformer.Informer(),
		oauthClientLister:   oauthv1listers.NewOAuthClientLister(oauthClientsSwitchedInformer.Informer().GetIndexer()),
		routeLister:         routeInformers.Route().V1().Routes().Lister(),
		ingressLister:       operatorConfigInformers.Config().V1().Ingresses().Lister(),
		authConfigChecker:   authConfigChecker,
	}

	return factory.New().
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		WithFilteredEventsInformers(
			factory.NamesFilter("openshift-browser-client", "openshift-challenging-client", "openshift-cli-client"),
			oauthClientsSwitchedInformer.Informer(),
		).
		WithFilteredEventsInformers(
			factory.NamesFilter("oauth-openshift"),
			routeInformers.Route().V1().Routes().Informer(),
		).
		WithInformers(
			operatorConfigInformers.Config().V1().Ingresses().Informer(),
			authConfigChecker.Authentications().Informer(),
			authConfigChecker.KubeAPIServers().Informer(),
		).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController("OAuthClientsController", eventRecorder.WithComponentSuffix("oauth-clients-controller"))
}

func (c *oauthsClientsController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		return c.ensureBootstrappedOAuthClientsMissing(ctx)
	}

	ingress, err := c.getIngressConfig()
	if err != nil {
		return err
	}
	ingressConfigCopy := ingress.DeepCopy()

	hostname := common.GetCustomRouteHostname(ingressConfigCopy, customroute.OAuthComponentRouteNamespace, customroute.OAuthComponentRouteName)
	if hostname == "" {
		hostname = "oauth-openshift." + ingress.Spec.Domain
	}

	routeHost, err := c.getCanonicalRouteHost(hostname)
	if err != nil {
		return err
	}

	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !cache.WaitForCacheSync(waitCtx.Done(), c.oauthClientInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for OAuthClients informer cache sync")
	}

	return c.ensureBootstrappedOAuthClients(ctx, "https://"+routeHost)
}

func (c *oauthsClientsController) getIngressConfig() (*configv1.Ingress, error) {
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster ingress config: %v", err)
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, fmt.Errorf("the ingress config domain cannot be empty")
	}
	return ingress, nil
}

func (c *oauthsClientsController) getCanonicalRouteHost(expectedHost string) (string, error) {
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return "", err
	}

	routeHost, _, err := routeapihelpers.IngressURI(route, expectedHost)
	if err != nil {
		return "", err
	}
	return routeHost.Host, nil
}

func (c *oauthsClientsController) ensureBootstrappedOAuthClients(ctx context.Context, masterPublicURL string) error {
	for _, client := range []oauthv1.OAuthClient{
		{
			ObjectMeta:            metav1.ObjectMeta{Name: "openshift-browser-client"},
			Secret:                base64.RawURLEncoding.EncodeToString(randomBits(256)),
			RespondWithChallenges: false,
			RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenDisplayURL(masterPublicURL)},
			GrantMethod:           oauthv1.GrantHandlerAuto,
		},
		{
			ObjectMeta:            metav1.ObjectMeta{Name: "openshift-challenging-client"},
			Secret:                "",
			RespondWithChallenges: true,
			RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenImplicitURL(masterPublicURL)},
			GrantMethod:           oauthv1.GrantHandlerAuto,
		},
		{
			ObjectMeta:   metav1.ObjectMeta{Name: "openshift-cli-client"},
			RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
			GrantMethod:  oauthv1.GrantHandlerAuto,
		},
	} {
		if err := c.ensureOAuthClient(ctx, client); err != nil {
			return fmt.Errorf("unable to ensure existence of a bootstrapped OAuth client %q: %w", client.Name, err)
		}
	}

	return nil
}

func (c *oauthsClientsController) ensureBootstrappedOAuthClientsMissing(ctx context.Context) error {
	for _, clientName := range []string{
		"openshift-browser-client",
		"openshift-challenging-client",
		"openshift-cli-client",
	} {
		_, err := c.oauthClientLister.Get(clientName)
		if errors.IsNotFound(err) {
			continue
		} else if err != nil {
			return err
		}

		if err := c.oauthClientClient.Delete(ctx, clientName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func randomBits(bits uint) []byte {
	size := bits / 8
	if bits%8 != 0 {
		size++
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

func (c *oauthsClientsController) ensureOAuthClient(ctx context.Context, client oauthv1.OAuthClient) error {
	_, err := c.oauthClientLister.Get(client.Name)
	if apierrors.IsNotFound(err) {
		_, err = c.oauthClientClient.Create(ctx, &client, metav1.CreateOptions{})
		return err
	}

	if err != nil {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := c.oauthClientLister.Get(client.Name)
		if err != nil {
			return err
		}

		existingCopy := existing.DeepCopy()

		if len(client.Secret) == 0 {
			existingCopy.Secret = ""
		}
		if len(existingCopy.Secret) < len(client.Secret) {
			existingCopy.Secret = client.Secret
		}

		existingCopy.RespondWithChallenges = client.RespondWithChallenges
		existingCopy.RedirectURIs = client.RedirectURIs
		existingCopy.GrantMethod = client.GrantMethod
		existingCopy.ScopeRestrictions = client.ScopeRestrictions

		if equality.Semantic.DeepEqual(existing, existingCopy) {
			return nil
		}

		_, err = c.oauthClientClient.Update(ctx, existingCopy, metav1.UpdateOptions{})
		return err
	})
}
