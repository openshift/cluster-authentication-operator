package webhookauthenticator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog/v2"

	"github.com/openshift/api/annotations"
	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/bindata"
)

// webhookAuthenticatorController makes sure that the webhook token authenticators
// are configured so that they point to the oauth-apiserver's tokenvalidation
// endpoint. That is, if the type of authentication in the auth config is set t
// be the integrated authentication
type webhookAuthenticatorController struct {
	controllerInstanceName string
	authentication         configv1client.AuthenticationInterface
	serviceAccounts        corev1client.ServiceAccountsGetter

	saLister      corev1listers.ServiceAccountLister
	svcLister     corev1listers.ServiceLister
	secrets       corev1client.SecretsGetter
	secretsLister corev1listers.SecretLister

	operatorClient v1helpers.OperatorClient

	apiServerVersionWaitEventsLimiter flowcontrol.RateLimiter
	versionGetter                     status.VersionGetter
}

func NewWebhookAuthenticatorController(
	instanceName string,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	configInformer configinformers.SharedInformerFactory,
	secrets corev1client.SecretsGetter,
	serviceAccounts corev1client.ServiceAccountsGetter,
	authentication configv1client.AuthenticationInterface,
	operatorClient v1helpers.OperatorClient,
	versionGetter status.VersionGetter,
	recorder events.Recorder,
) factory.Controller {
	c := &webhookAuthenticatorController{
		controllerInstanceName:            factory.ControllerInstanceName(instanceName, "WebhookAuthenticator"),
		secrets:                           secrets,
		serviceAccounts:                   serviceAccounts,
		secretsLister:                     kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		svcLister:                         kubeInformersForTargetNamespace.Core().V1().Services().Lister(),
		saLister:                          kubeInformersForTargetNamespace.Core().V1().ServiceAccounts().Lister(),
		authentication:                    authentication,
		operatorClient:                    operatorClient,
		apiServerVersionWaitEventsLimiter: flowcontrol.NewTokenBucketRateLimiter(0.0167, 1), // set it so that the event may only occur once per minute
		versionGetter:                     versionGetter,
	}
	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().ServiceAccounts().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Services().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
	).ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController(
			"WebhookAuthenticatorController", // Don't change what is passed here unless you also remove the old FooDegraded condition
			recorder.WithComponentSuffix("webhook-authenticator-controller"))
}

func (c *webhookAuthenticatorController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	// TODO: remove in 4.9; this is to ensure we don't configure webhook authenticators
	// before the oauth-apiserver revision that's capable of handling it is ready
	// during upgrade
	versions := c.versionGetter.GetVersions()
	if apiserverVersion, ok := versions["oauth-apiserver"]; ok {
		// a previous version found means this could be an upgrade, unless the version is already current
		if expectedVersion := os.Getenv("OPERATOR_IMAGE_VERSION"); apiserverVersion != expectedVersion {
			if c.apiServerVersionWaitEventsLimiter.TryAccept() {
				syncCtx.Recorder().Eventf("OAuthAPIServerWaitForLatest", "the oauth-apiserver hasn't reported its version to be %q yet, its current version is %q", expectedVersion, apiserverVersion)
			}
			return nil
		}
	}

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
		return fmt.Errorf("failed to retrieve service openshift-oauth-apiserver/api: %w", err)
	}

	kubeConfigSecret, err := c.ensureKubeConfigSecret(ctx, oauthAPIsvc, syncCtx.Recorder())
	if kubeConfigSecret == nil {
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

// ensureKubeConfigSecret attempts to retrieve a certificate and a key from the
// openshift-oauth-apiserver/openshift-authenticator-certs secret. It feeds these
// credentials for client-cert auth to a kubeconfig pointing to the oauth-apiserver's
// tokenvalidation endpoint so that it can then push this kubeconfig into
// openshift-config/webhook-authentication-integrated-oauth secret
func (c *webhookAuthenticatorController) ensureKubeConfigSecret(ctx context.Context, svc *corev1.Service, recorder events.Recorder) (*corev1.Secret, error) {
	key, cert, err := c.getAuthenticatorCertKeyPair(ctx)
	if key == nil || cert == nil {
		return nil, err
	}

	caBundle, err := ioutil.ReadFile("/var/run/configmaps/service-ca-bundle/service-ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read service-ca crt bundle: %w", err)
	}

	kubeconfigBytes, err := bindata.Asset("oauth-apiserver/authenticator-kubeconfig.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read kubeconfig template: %w", err)
	}

	replacer := strings.NewReplacer(
		"${CA_DATA}", base64.StdEncoding.EncodeToString(caBundle),
		"${APISERVER_IP}", net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port))),
		"${CLIENT_CERT}", base64.StdEncoding.EncodeToString(cert),
		"${CLIENT_KEY}", base64.StdEncoding.EncodeToString(key),
	)

	kubeconfigComplete := replacer.Replace(string(kubeconfigBytes))

	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("private key doesn't match the certificate of authenticator secret")
	}
	// extract not-before/not-after timestamps valid x509 certificate
	var block *pem.Block
	block, _ = pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("invalid first block found in the certificate of authenticator secret")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the certificate of authenticator secret")
	}

	requiredSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-authentication-integrated-oauth",
			Namespace: "openshift-config",
			Annotations: map[string]string{
				annotations.OpenShiftComponent:              "apiserver-auth",
				certrotation.CertificateNotBeforeAnnotation: parsedCert.NotBefore.Format(time.RFC3339),
				certrotation.CertificateNotAfterAnnotation:  parsedCert.NotAfter.Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"kubeConfig": []byte(kubeconfigComplete),
		},
	}

	secret, _, err := resourceapply.ApplySecret(ctx, c.secrets, recorder, requiredSecret)
	return secret, err
}

func (c *webhookAuthenticatorController) getAuthenticatorCertKeyPair(ctx context.Context) (key, cert []byte, err error) {
	// waitingForCertKeyMsg lets us decide whether we should set progressing condition to true
	// 1. nil: keep "progressing the same"
	// 2. non-empty string: progress with the message in the string
	// 3. empty string: stop progressing
	var waitingForCertKeyMsg *string
	defer func() {
		if waitingForCertKeyMsg == nil {
			return
		}
		cond := applyoperatorv1.OperatorCondition().
			WithType("AuthenticatorCertKeyProgressing").
			WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected").
			WithMessage("All is well")

		if len(*waitingForCertKeyMsg) > 0 {
			cond = cond.
				WithStatus(operatorv1.ConditionTrue).
				WithReason("WaitingForCertKey").
				WithMessage(*waitingForCertKeyMsg)
		}

		status := applyoperatorv1.OperatorStatus().WithConditions(cond)
		if statusErr := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); statusErr != nil {
			klog.Errorf("failed to update operator status: %v", statusErr)
			err = statusErr
		}
	}()

	certSecret, err := c.secretsLister.Secrets("openshift-oauth-apiserver").Get("openshift-authenticator-certs")
	if err != nil {
		if apierrors.IsNotFound(err) {
			waitingForCertKeyMsg = pstr("waiting for the cert/key secret openshift-oauth-apiserver/openshift-authenticator-certs to appear")
			return nil, nil, nil
		}
		return nil, nil, err
	}

	key, ok := certSecret.Data["tls.key"]
	if !ok {
		waitingForCertKeyMsg = pstr("the authenticator's client cert secret is missing the 'tls.key' key")
		return nil, nil, nil
	}

	cert, ok = certSecret.Data["tls.crt"]
	if !ok {
		waitingForCertKeyMsg = pstr("the authenticator's client cert secret is missing the 'tls.crt' key")
		return nil, nil, nil
	}

	// stop progressing on the cert/key secret
	waitingForCertKeyMsg = pstr("")
	return key, cert, nil
}

func pstr(s string) *string {
	return &s
}
