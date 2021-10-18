package serviceca

import (
	"context"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1lister "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"OAuthServiceDegraded",
	"SystemServiceCAConfigDegraded",
)

type serviceCAController struct {
	serviceLister  corev1lister.ServiceLister
	secretLister   corev1lister.SecretLister
	configMaps     corev1client.ConfigMapsGetter
	operatorClient v1helpers.OperatorClient
}

func NewServiceCAController(kubeInformersForTargetNamespace informers.SharedInformerFactory, configInformer configinformers.SharedInformerFactory, configMaps corev1client.ConfigMapsGetter,
	operatorClient v1helpers.OperatorClient, recorder events.Recorder) factory.Controller {
	c := &serviceCAController{
		serviceLister:  kubeInformersForTargetNamespace.Core().V1().Services().Lister(),
		secretLister:   kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		configMaps:     configMaps,
		operatorClient: operatorClient,
	}
	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Services().Informer(),
		kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
		configInformer.Config().V1().Ingresses().Informer(),
	).ResyncEvery(30*time.Second).WithSync(c.sync).ToController("ServiceCAController", recorder.WithComponentSuffix("service-ca-controller"))
}

func (c *serviceCAController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	_, serviceConditions := common.GetOAuthServerService(c.serviceLister, "OAuthService")
	foundConditions = append(foundConditions, serviceConditions...)

	if len(foundConditions) == 0 {
		serviceCAConditions, err := c.getServiceCA(ctx, syncCtx.Recorder())
		if err != nil {
			return err
		}
		foundConditions = append(foundConditions, serviceCAConditions...)
	}

	return common.UpdateControllerConditions(ctx, c.operatorClient, knownConditionNames, foundConditions)
}

func getServiceCAConfig() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "v4-0-config-system-service-ca",
			Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"},
			Namespace:   "openshift-authentication",
			Labels: map[string]string{
				"app": "oauth-openshift",
			},
			OwnerReferences: nil, // TODO
		},
	}
}

func (c *serviceCAController) getServiceCA(ctx context.Context, recorder events.Recorder) ([]operatorv1.OperatorCondition, error) {
	cm := c.configMaps.ConfigMaps("openshift-authentication")
	secret := c.secretLister.Secrets("openshift-authentication")
	serviceCA, err := cm.Get(ctx, "v4-0-config-system-service-ca", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = cm.Create(ctx, getServiceCAConfig(), metav1.CreateOptions{})
	}
	if err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "SystemServiceCAConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Error",
			Message: fmt.Sprintf("Unable to get or create system service CA config %q: %v", "v4-0-config-system-service-ca", err),
		}}, nil
	}

	if len(serviceCA.Data["service-ca.crt"]) == 0 {
		return []operatorv1.OperatorCondition{{
			Type:    "SystemServiceCAConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "MissingCA",
			Message: fmt.Sprintf("Config %q has no service CA data", serviceCA.Name),
		}}, nil
	}

	if serviceCA.Annotations["service.alpha.openshift.io/inject-cabundle"] != "true" {
		// return fmt.Errorf("config map missing injection annotation: %#v", ca)
		// delete the service CA config map so that it is replaced with the proper one in next reconcile loop
		opts := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &serviceCA.UID}}
		if err := cm.Delete(ctx, serviceCA.Name, opts); err != nil && !errors.IsNotFound(err) {
			recorder.Warningf("InvalidServiceCAFailed", "Failed to delete invalid service CA config map %s: %v", spew.Sdump(serviceCA), err)
			return nil, err
		}
		recorder.Eventf("InvalidServiceCA", "Deleted serviced CA config map because the inject-cabundle annotation was missing: %s", spew.Sdump(serviceCA.Annotations))
		return nil, factory.SyntheticRequeueError
	}

	if _, err = secret.Get("v4-0-config-system-serving-cert"); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "SystemServiceCAConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "MissingSystemServingCert",
			Message: fmt.Sprintf("Failed to get system serving cert secret %q: %v", "v4-0-config-system-serving-cert", err),
		}}, nil
	}

	return nil, nil
}
