package webhookauthenticator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/assets"
)

// webhookAuthenticatorController makes sure that the webhook token authenticators
// are configured so that they point to the oauth-apiserver's tokenvalidation
// endpoint. That is, if the type of authentication in the auth config is set t
// be the integrated authentication
type webhookAuthenticatorController struct {
	authentication  configv1client.AuthenticationInterface
	serviceAccounts corev1client.ServiceAccountsGetter

	saLister  corev1listers.ServiceAccountLister
	svcLister corev1listers.ServiceLister
	secrets   corev1client.SecretsGetter

	operatorConfigClient operatorconfigclient.AuthenticationsGetter
	operatorClient       v1helpers.OperatorClient
}

func NewWebhookAuthenticatorController(
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	configInformer configinformers.SharedInformerFactory,
	secrets corev1client.SecretsGetter,
	serviceAccounts corev1client.ServiceAccountsGetter,
	authentication configv1client.AuthenticationInterface,
	operatorConfigClient operatorconfigclient.AuthenticationsGetter,
	operatorClient v1helpers.OperatorClient,
	recorder events.Recorder,
) factory.Controller {
	c := &webhookAuthenticatorController{
		secrets:              secrets,
		serviceAccounts:      serviceAccounts,
		svcLister:            kubeInformersForTargetNamespace.Core().V1().Services().Lister(),
		saLister:             kubeInformersForTargetNamespace.Core().V1().ServiceAccounts().Lister(),
		authentication:       authentication,
		operatorConfigClient: operatorConfigClient,
		operatorClient:       operatorClient,
	}
	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().ServiceAccounts().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Services().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
	).ResyncEvery(30*time.Second).
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController("WebhookAuthenticatorController", recorder.WithComponentSuffix("webhook-authenticator-controller"))
}

func (c *webhookAuthenticatorController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	authConfig, err := c.authentication.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return err
	}

	if authConfig.Spec.Type != configv1.AuthenticationTypeIntegratedOAuth && len(authConfig.Spec.Type) != 0 {
		// not using integrated openshift auth
		return nil
	}

	oauthAPIsvc, err := c.svcLister.Services("openshift-oauth-apiserver").Get("api")
	if err != nil {
		return fmt.Errorf("failed to retrieve service openshift-oauth-apiserver/oauth-apiserver: %w", err)
	}

	kubeConfigSecret, err := c.ensureKubeConfigSecret(ctx, oauthAPIsvc, syncCtx.Recorder())
	if err != nil {
		return err
	}

	if authConfig.Spec.WebhookTokenAuthenticator == nil {
		authConfig.Spec.WebhookTokenAuthenticator = &configv1.WebhookTokenAuthenticator{}
	}

	if authConfig.Spec.WebhookTokenAuthenticator.KubeConfig.Name != kubeConfigSecret.Name {
		authConfigCopy := authConfig.DeepCopy()
		authConfigCopy.Spec.WebhookTokenAuthenticator.KubeConfig.Name = kubeConfigSecret.Name
		_, err := c.authentication.Update(ctx, authConfigCopy, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

// ensureKubeConfigSecret retrieves the token from a secret for the
// openshift-oauth-apiserver/openshift-authenticator SA. It checks that the
// "service-ca.crt" and "token" keys are present and creates a
// openshift-config/webhook-authentication-integrated-oauth secret with a kubeconfig
// pointing to the oauth-apiserver's tokenvalidation endpoint
func (c *webhookAuthenticatorController) ensureKubeConfigSecret(ctx context.Context, svc *corev1.Service, recorder events.Recorder) (*corev1.Secret, error) {
	sa, err := c.saLister.ServiceAccounts("openshift-oauth-apiserver").Get("openshift-authenticator")
	if err != nil {
		return nil, err
	}

	if len(sa.Secrets) == 0 {
		return nil, fmt.Errorf("SA openshift-authenticator does not have any tokens assigned")
	}

	var tokenSecretName string
	for _, saSecret := range sa.Secrets {
		if strings.Contains(saSecret.Name, "token") {
			tokenSecretName = saSecret.Name
		}
	}

	if len(tokenSecretName) == 0 {
		return nil, fmt.Errorf("SA openshift-authenticator does not have any tokens assigned")
	}

	tokenSecret, err := c.secrets.Secrets("openshift-oauth-apiserver").Get(ctx, tokenSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	caBundle, ok := tokenSecret.Data["service-ca.crt"]
	if !ok {
		return nil, fmt.Errorf("service-account token secret is missing the 'ca.crt' key")
	}
	token, ok := tokenSecret.Data["token"]
	if !ok {
		return nil, fmt.Errorf("service-account token secret is missing the 'token' key")
	}

	kubeconfigBytes, err := assets.Asset("oauth-apiserver/authenticator-kubeconfig.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read kubeconfig template: %w", err)
	}

	replacer := strings.NewReplacer(
		"${CA_DATA}", base64.StdEncoding.EncodeToString(caBundle),
		"${APISERVER_IP}", net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port))),
		"${AUTHENTICATOR_TOKEN}", string(token),
	)

	kubeconfigComplete := replacer.Replace(string(kubeconfigBytes))

	requiredSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-authentication-integrated-oauth",
			Namespace: "openshift-config",
		},
		Data: map[string][]byte{
			"kubeConfig": []byte(kubeconfigComplete),
		},
	}

	secret, _, err := resourceapply.ApplySecret(c.secrets, recorder, requiredSecret)
	return secret, err
}
