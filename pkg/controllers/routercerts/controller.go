package routercerts

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"time"

	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerWorkQueueKey           = "key"
	conditionRouterCertsDegradedType = "RouterCertsDegraded"
)

// RouterCertsDomainValidationController validates that router certs match the ingress domain
type RouterCertsDomainValidationController struct {
	operatorClient v1helpers.OperatorClient
	cachesToSync   []cache.InformerSynced
	queue          workqueue.RateLimitingInterface
	eventRecorder  events.Recorder

	ingressLister   configv1listers.IngressLister
	secretLister    corev1listers.SecretLister
	targetNamespace string
	secretName      string
	routeName       string

	systemCertPool func() (*x509.CertPool, error) // enables unit testing
}

func NewRouterCertsDomainValidationController(
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
	ingressInformer configv1informers.IngressInformer,
	secretInformer corev1informers.SecretInformer,
	targetNamespace string,
	secretName string,
	routeName string,
) *RouterCertsDomainValidationController {
	controller := &RouterCertsDomainValidationController{
		operatorClient:  operatorClient,
		cachesToSync:    nil,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "RouterCertsDomainValidationController"),
		eventRecorder:   eventRecorder,
		ingressLister:   ingressInformer.Lister(),
		secretLister:    secretInformer.Lister(),
		targetNamespace: targetNamespace,
		secretName:      secretName,
		routeName:       routeName,
		systemCertPool:  x509.SystemCertPool,
	}
	operatorClient.Informer().AddEventHandler(controller.newEventHandler())
	ingressInformer.Informer().AddEventHandler(controller.newEventHandler())
	secretInformer.Informer().AddEventHandler(controller.newEventHandler())
	controller.cachesToSync = append(controller.cachesToSync,
		operatorClient.Informer().HasSynced,
		ingressInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	)
	return controller
}

func (c *RouterCertsDomainValidationController) sync() error {
	spec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if !management.IsOperatorManaged(spec.ManagementState) {
		return nil
	}

	condition := c.validateRouterCertificates()
	if _, _, err = v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(condition)); err != nil {
		return err
	}

	return nil
}

func (c *RouterCertsDomainValidationController) validateRouterCertificates() operatorv1.OperatorCondition {
	// get ingress
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return newRouterCertsDegradedf("NoIngressConfig", "ingresses.config.openshift.io/cluster could not be retrieved: %v", err)
	}

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

	// categorize certificates
	var serverCerts []*x509.Certificate
	verifyOptions := x509.VerifyOptions{}
	verifyOptions.DNSName = c.routeName + "." + ingressDomain
	verifyOptions.Intermediates = x509.NewCertPool()
	verifyOptions.Roots, err = c.systemCertPool()
	if err != nil {
		klog.Infof("system cert pool not available: %v", err)
		verifyOptions.Roots = x509.NewCertPool()
	}
	for _, certificate := range certificates {
		switch {
		case certificate.IsCA && bytes.Equal(certificate.RawSubject, certificate.RawIssuer):
			klog.V(4).Infof("using CA %s as root", certificate.Subject.String())
			verifyOptions.Roots.AddCert(certificate)
		case certificate.IsCA:
			klog.V(4).Infof("using CA %s as intermediate", certificate.Subject.String())
			verifyOptions.Intermediates.AddCert(certificate)
		default:
			serverCerts = append(serverCerts, certificate)
		}
	}

	if len(verifyOptions.Roots.Subjects()) == 0 {
		return newRouterCertsDegradedf("NoRootCARouterCerts", "secret/%v.spec.data[%v] -n %v: no root CA certificates found in secret or system", c.secretName, ingressDomain, c.targetNamespace)
	}

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

func (c *RouterCertsDomainValidationController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting RouterCertsDomainValidationController")
	defer klog.Infof("Shutting down RouterCertsDomainValidationController")
	if !cache.WaitForCacheSync(ctx.Done(), c.cachesToSync...) {
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
}

func (c *RouterCertsDomainValidationController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *RouterCertsDomainValidationController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// newEventHandler returns an event handler that queues the operator to check spec and status
func (c *RouterCertsDomainValidationController) newEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(controllerWorkQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(controllerWorkQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(controllerWorkQueueKey) },
	}
}
