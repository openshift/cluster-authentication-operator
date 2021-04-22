package routercerts

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1clients "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/controller/factory"
)

const (
	conditionRouterCertsDegradedType = "RouterCertsDegraded"
)

// routerCertsDomainValidationController validates that router certs match the ingress domain
type routerCertsDomainValidationController struct {
	operatorClient  v1helpers.OperatorClient
	secretsClient   corev1clients.SecretsGetter
	ingressLister   configv1listers.IngressLister
	secretLister    corev1listers.SecretLister
	configMapLister corev1listers.ConfigMapLister
	targetNamespace string
	secretName      string
	routeName       string

	systemCertPool func() (*x509.CertPool, error) // enables unit testing
}

func NewRouterCertsDomainValidationController(
	operatorClient v1helpers.OperatorClient,
	secretsClient corev1clients.SecretsGetter,
	eventRecorder events.Recorder,
	ingressInformer configv1informers.IngressInformer,
	targetNSsecretInformer corev1informers.SecretInformer,
	machineConfigNSSecretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	targetNamespace string,
	secretName string,
	routeName string,
) factory.Controller {
	controller := &routerCertsDomainValidationController{
		operatorClient:  operatorClient,
		secretsClient:   secretsClient,
		ingressLister:   ingressInformer.Lister(),
		secretLister:    targetNSsecretInformer.Lister(),
		configMapLister: configMapInformer.Lister(),
		targetNamespace: targetNamespace,
		secretName:      secretName,
		routeName:       routeName,
		systemCertPool:  x509.SystemCertPool,
	}

	return factory.New().
		WithInformers(
			operatorClient.Informer(),
			ingressInformer.Informer(),
			targetNSsecretInformer.Informer(),
			configMapInformer.Informer()).
		WithFilteredEventsInformers(
			common.NamesFilter("router-certs"),
			machineConfigNSSecretInformer.Informer(),
		).
		WithSync(controller.sync).
		WithSyncDegradedOnError(operatorClient).
		ResyncEvery(30*time.Second).
		ToController("RouterCertsDomainValidationController", eventRecorder)
}

func (c *routerCertsDomainValidationController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	spec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if !management.IsOperatorManaged(spec.ManagementState) {
		return nil
	}

	// set the condition anywhere in sync() to update the controller's degraded condition
	var condition operatorv1.OperatorCondition
	defer func() {
		_, _, err = v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(condition))
	}()

	// get ingress
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		condition = newRouterCertsDegradedf("NoIngressConfig", "ingresses.config.openshift.io/cluster could not be retrieved: %v", err)
		return nil
	}

	// add syncing for router certs for all cluster ingresses
	if _, _, err := resourceapply.SyncPartialSecret(
		c.secretsClient,
		syncCtx.Recorder(),
		"openshift-config-managed", "router-certs",
		"openshift-authentication", "v4-0-config-system-router-certs",
		sets.NewString(ingress.Spec.Domain),
		nil,
	); err != nil {
		return err
	}

	condition = c.validateRouterCertificates(ingress)
	return nil
}

func (c *routerCertsDomainValidationController) validateRouterCertificates(ingress *configv1.Ingress) operatorv1.OperatorCondition {
	// get ingress domain
	ingressDomain := ingress.Spec.Domain
	if len(ingressDomain) == 0 {
		return newRouterCertsDegradedf("NoIngressDomain", "ingresses.config.openshift.io/cluster: no spec.domain specified")
	}

	// get router certs secret
	secret, err := c.secretLister.Secrets(c.targetNamespace).Get(c.secretName)
	if err != nil {
		return newRouterCertsDegradedf("NoRouterCertSecret", "secret/%v -n %v: could not be retrieved: %v", c.secretName, c.targetNamespace, err)
	}

	// cert data should exist
	data := secret.Data[ingressDomain]
	if len(data) == 0 {
		return newRouterCertsDegradedf("MissingRouterCertsPEM", "secret/%v.spec.data[%v] -n %v: not found", c.secretName, ingressDomain, c.targetNamespace)
	}

	// certificates should be parse-able
	certificates, err := crypto.CertsFromPEM(data)
	if err != nil {
		return newRouterCertsDegradedf("MalformedRouterCertsPEM", "secret/%v.spec.data[%v] -n %v: certificates could not be parsed: %v", c.secretName, ingressDomain, c.targetNamespace, err)
	}

	// get default router CA cert cm
	cm, err := c.configMapLister.ConfigMaps("openshift-config-managed").Get("default-ingress-cert")
	if err != nil {
		return newRouterCertsDegradedf("NoDefaultIngressCAConfigMap", "failed to get configMap openshift-config-managed/default-ingress-cert: %v", err)
	}

	ingressCABundlePEM, ok := cm.Data["ca-bundle.crt"]
	if !ok {
		return newRouterCertsDegraded("MissingIngressCACerts", "configMap/default-ingress-cert.data[ca-bundle.crt] -n openshift-config-managed: empty")
	}

	ingressCACerts, err := crypto.CertsFromPEM([]byte(ingressCABundlePEM))
	if err != nil {
		return newRouterCertsDegradedf("MalformedIngressCACertsPem", "configMap/default-ingress-cert.data[ca-bundle.crt] -n openshift-config-managed: certificates could not be parsed: %v", err)
	}

	// categorize certificates
	verifyOptions := x509.VerifyOptions{}
	verifyOptions.DNSName = c.routeName + "." + ingressDomain
	verifyOptions.Intermediates = x509.NewCertPool()
	verifyOptions.Roots, err = c.systemCertPool()
	if err != nil {
		klog.Infof("system cert pool not available: %v", err)
		verifyOptions.Roots = x509.NewCertPool()
	}
	// ignore the server cert from the default cert bundle
	populateVerifyOptionsFromCertSlice(&verifyOptions, ingressCACerts)
	if len(verifyOptions.Roots.Subjects()) == 0 { // the CA certs can also appear in the secret, but by default we should also trust the default ingress CA bundle for the default routes
		return newRouterCertsDegradedf("NoRootCARouterCerts", "configMap/default-ingress-cert.data[ca-bundle.crt] -n openshift-config-managed: no root CA certificates found in the CM or system")
	}

	serverCerts := populateVerifyOptionsFromCertSlice(&verifyOptions, certificates)
	if len(serverCerts) == 0 {
		return newRouterCertsDegradedf("NoServerCertRouterCerts", "secret/%v.spec.data[%v] -n %v: no server certificates found", c.secretName, ingressDomain, c.targetNamespace)
	}

	// verify certificate chain
	if err := verifyWithAnyCertificate(serverCerts, verifyOptions); err != nil {
		return newRouterCertsDegradedf("InvalidServerCertRouterCerts", "secret/%v.spec.data[%v] -n %v: certificate could not validate route hostname %v: %v", c.secretName, ingressDomain, c.targetNamespace, verifyOptions.DNSName, err)
	}

	// we made it this far without a problem
	return operatorv1.OperatorCondition{
		Type:   conditionRouterCertsDegradedType,
		Status: operatorv1.ConditionFalse,
		Reason: "AsExpected",
	}

}

func newRouterCertsDegradedf(reason, message string, args ...interface{}) operatorv1.OperatorCondition {
	return newRouterCertsDegraded(reason, fmt.Sprintf(message, args...))
}

func newRouterCertsDegraded(reason, message string) operatorv1.OperatorCondition {
	return operatorv1.OperatorCondition{
		Type:    conditionRouterCertsDegradedType,
		Status:  operatorv1.ConditionTrue,
		Reason:  reason,
		Message: message,
	}
}

func verifyWithAnyCertificate(serverCerts []*x509.Certificate, options x509.VerifyOptions) error {
	var err error
	for _, certificate := range serverCerts {
		_, err = certificate.Verify(options)
		if err == nil {
			klog.V(4).Infof("cert %s passed verification", certificate.Subject.String())
			return nil
		}
		klog.V(4).Infof("cert %s failed verification: %v", certificate.Subject.String(), err)
	}
	// no certificate was able to verify dns name, return last error
	return err
}

func populateVerifyOptionsFromCertSlice(opts *x509.VerifyOptions, certs []*x509.Certificate) []*x509.Certificate {
	serverCerts := []*x509.Certificate{}
	for _, certificate := range certs {
		switch {
		case certificate.IsCA && bytes.Equal(certificate.RawSubject, certificate.RawIssuer):
			klog.V(4).Infof("using CA %s as root", certificate.Subject.String())
			opts.Roots.AddCert(certificate)
		case certificate.IsCA:
			klog.V(4).Infof("using CA %s as intermediate", certificate.Subject.String())
			opts.Intermediates.AddCert(certificate)
		default:
			serverCerts = append(serverCerts, certificate)
		}
	}

	return serverCerts
}
