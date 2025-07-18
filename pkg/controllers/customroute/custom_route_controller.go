package customroute

import (
	"context"
	"fmt"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	configsetterv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformersv1 "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/bindata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/datasync"
)

const (
	OAuthComponentRouteName      = "oauth-openshift"
	OAuthComponentRouteNamespace = "openshift-authentication"
)

type customRouteController struct {
	destSecret        types.NamespacedName
	componentRoute    types.NamespacedName
	ingressLister     configlistersv1.IngressLister
	ingressClient     configsetterv1.IngressInterface
	routeLister       routev1lister.RouteLister
	routeClient       routeclient.RouteInterface
	secretLister      corev1listers.SecretLister
	resourceSyncer    resourcesynccontroller.ResourceSyncer
	operatorClient    v1helpers.OperatorClient
	authConfigChecker common.AuthConfigChecker
}

func NewCustomRouteController(
	componentRouteNamespace string,
	componentRouteName string,
	destSecretNamespace string,
	destSecretName string,
	ingressInformer configinformersv1.IngressInformer,
	ingressClient configsetterv1.IngressInterface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteInterface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	operatorClient v1helpers.OperatorClient,
	authConfigChecker common.AuthConfigChecker,
	eventRecorder events.Recorder,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
) factory.Controller {
	controller := &customRouteController{
		destSecret: types.NamespacedName{
			Namespace: destSecretNamespace,
			Name:      destSecretName,
		},
		componentRoute: types.NamespacedName{
			Namespace: componentRouteNamespace,
			Name:      componentRouteName,
		},
		ingressLister:     ingressInformer.Lister(),
		ingressClient:     ingressClient,
		routeLister:       routeInformer.Lister(),
		routeClient:       routeClient,
		secretLister:      kubeInformersForNamespaces.SecretLister(),
		operatorClient:    operatorClient,
		resourceSyncer:    resourceSyncer,
		authConfigChecker: authConfigChecker,
	}

	return factory.New().
		WithInformers(
			ingressInformer.Informer(),
			routeInformer.Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-config").Core().V1().Secrets().Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-authentication").Core().V1().Secrets().Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		WithSyncDegradedOnError(operatorClient).
		WithSync(controller.sync).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController("CustomRouteController", eventRecorder.WithComponentSuffix("custom-route-controller"))
}

func (c *customRouteController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	ingressConfig, err := c.ingressLister.Get("cluster")
	if err != nil {
		return err
	}

	ingressConfigCopy := ingressConfig.DeepCopy()

	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		return c.removeOperands(ctx, ingressConfigCopy)
	}

	// configure the expected route
	expectedRoute, secretName, errors := c.getOAuthRouteAndSecretName(ingressConfigCopy)
	if errors != nil {
		// log if there is an issue updating the ingressConfig resource
		if updateIngressConfigErr := c.updateIngressConfigStatus(ctx, ingressConfigCopy, errors); updateIngressConfigErr != nil {
			klog.Infof("Error updating ingress with custom route status: %v", err)
		}
		return fmt.Errorf("custom route configuration failed verification: %v", errors)
	}

	// create or modify the existing route
	if err = c.applyRoute(ctx, expectedRoute); err != nil {
		return err
	}

	// update ingressConfig status
	if err = c.updateIngressConfigStatus(ctx, ingressConfigCopy, nil); err != nil {
		return err
	}

	// sync the secret
	return c.syncSecret(secretName)
}

func (c *customRouteController) getOAuthRouteAndSecretName(ingressConfig *configv1.Ingress) (*routev1.Route, string, []error) {
	route := resourceread.ReadRouteV1OrDie(bindata.MustAsset("oauth-openshift/route.yaml"))
	// set defaults
	route.Spec.Host = "oauth-openshift." + ingressConfig.Spec.Domain // mimic the behavior of subdomain
	secretName := ""

	// check if a user is overriding route defaults
	if componentRoute := common.GetComponentRouteSpec(ingressConfig, OAuthComponentRouteNamespace, OAuthComponentRouteName); componentRoute != nil {
		var errors []error
		// Check if the provided secret is valid
		secretName = componentRoute.ServingCertKeyPairSecret.Name
		if err := c.validateCustomTLSSecret(secretName); err != nil {
			errors = append(errors, err)
		}

		// Check if the provided hostname is valid
		hostname := string(componentRoute.Hostname)
		if _, err := url.Parse(hostname); err != nil {
			errors = append(errors, err)
		}

		if errors != nil {
			return nil, "", errors
		}

		route.Spec.Host = hostname
	}

	return route, secretName, nil
}

func (c *customRouteController) validateCustomTLSSecret(secretName string) error {
	if secretName != "" {
		secret, err := c.secretLister.Secrets("openshift-config").Get(secretName)
		if err != nil {
			return err
		}

		var errors []error
		privateKeyData, ok := secret.Data[corev1.TLSPrivateKeyKey]
		if !ok {
			errors = append(errors, fmt.Errorf("custom route secret must include key %s", corev1.TLSPrivateKeyKey))
		} else {
			errors = append(errors, datasync.ValidatePrivateKey(privateKeyData)...)
		}

		certData, ok := secret.Data[corev1.TLSCertKey]
		if !ok {
			errors = append(errors, fmt.Errorf("custom route secret must include key %s", corev1.TLSCertKey))
		} else {
			errors = append(errors, datasync.ValidateServerCert(certData)...)
		}

		if len(errors) != 0 {
			return fmt.Errorf("error validating secret %s/%s: %v", "openshift-config", secretName, errors)
		}
	}
	return nil
}

func (c *customRouteController) applyRoute(ctx context.Context, expectedRoute *routev1.Route) error {
	route, err := c.routeClient.Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = c.routeClient.Create(ctx, expectedRoute, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	// assume it is unsafe to mutate route in case we go to a shared informer in the future
	existingCopy := route.DeepCopy()
	modified := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, expectedRoute.ObjectMeta)

	// this guarantees that route.Spec.Host is set to the current canonical host
	if *modified || !equality.Semantic.DeepEqual(existingCopy.Spec, expectedRoute.Spec) {
		// be careful not to print route.spec as it many contain secrets
		existingCopy.Spec = expectedRoute.Spec
		_, err = c.routeClient.Update(ctx, existingCopy, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *customRouteController) updateIngressConfigStatus(ctx context.Context, ingressConfig *configv1.Ingress, customRouteErrors []error) error {
	// update ingressConfig status
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return err
	}

	componentRoute := applyconfigv1.ComponentRouteStatus().
		WithNamespace(c.componentRoute.Namespace).
		WithName(c.componentRoute.Name).
		WithDefaultHostname(configv1.Hostname("oauth-openshift." + ingressConfig.Spec.Domain)).
		WithCurrentHostnames(configv1.Hostname(route.Spec.Host)).
		WithConsumingUsers("system:serviceaccount:oauth-openshift:authentication-operator").
		WithRelatedObjects(
			applyconfigv1.ObjectReference().
				WithNamespace("openshift-authentication").
				WithName("oauth-openshift").
				WithGroup(routev1.GroupName).
				WithResource("routes"),
		)

	newConditions := checkErrorsConfiguringCustomRoute(customRouteErrors)
	if newConditions == nil {
		newConditions = checkIngressURI(ingressConfig, route)
		if newConditions == nil {
			newConditions = checkRouteAvailablity(c.secretLister, ingressConfig, route)
		}
	}
	newConditions = ensureDefaultConditions(newConditions)
	// set timestamps to last transitioned if available, otherwise, write a new lasttransitioned.
	// this may not handle extremely rapid flapping well.
	if existingComponentRoute := common.GetComponentRouteStatus(ingressConfig, c.componentRoute.Namespace, c.componentRoute.Name); existingComponentRoute != nil {
		for i := range newConditions {
			newCondition := newConditions[i]
			if existingCondition := v1helpers.FindCondition(existingComponentRoute.Conditions, *newCondition.Type); existingCondition != nil {
				if *newCondition.Status == existingCondition.Status {
					newConditions[i].LastTransitionTime = &existingCondition.LastTransitionTime
				}
			}
		}
	}

	componentRoute.WithConditions(newConditions...)

	ingressStatus := applyconfigv1.Ingress(ingressConfig.Name).WithStatus(applyconfigv1.IngressStatus().WithComponentRoutes(componentRoute))
	_, err = c.ingressClient.ApplyStatus(ctx, ingressStatus, c.forceApply())
	return err
}

func (c *customRouteController) syncSecret(secretName string) error {
	source := resourcesynccontroller.ResourceLocation{}
	if secretName != "" {
		source = resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: secretName}
	}

	destination := resourcesynccontroller.ResourceLocation{Namespace: c.destSecret.Namespace, Name: c.destSecret.Name}

	return c.resourceSyncer.SyncSecret(destination, source)
}

func (c *customRouteController) forceApply() metav1.ApplyOptions {
	return metav1.ApplyOptions{
		Force:        true, // this control loop owns these fields
		FieldManager: c.getFieldManager(),
	}
}

func (c *customRouteController) getFieldManager() string {
	// TODO find a way to get the client name and combine it with the controller name automatically
	return "AuthenticationCustomRouteController"
}

func (c *customRouteController) removeOperands(ctx context.Context, ingressConfig *configv1.Ingress) error {
	if _, err := c.routeLister.Routes(c.componentRoute.Namespace).Get(c.componentRoute.Name); err != nil && !errors.IsNotFound(err) {
		return err
	} else if !errors.IsNotFound(err) {
		if err := c.routeClient.Delete(ctx, c.componentRoute.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	ingressStatus, err := applyconfigv1.ExtractIngressStatus(ingressConfig, c.getFieldManager())
	if err != nil {
		return err
	}

	if ingressStatus != nil && ingressStatus.Status != nil {
		componentRoutes := make([]applyconfigv1.ComponentRouteStatusApplyConfiguration, 0)
		routeFound := false
		for _, cr := range ingressStatus.Status.ComponentRoutes {
			if *cr.Name == c.componentRoute.Name && *cr.Namespace == c.componentRoute.Namespace {
				routeFound = true
				continue
			}

			componentRoutes = append(componentRoutes, cr)
		}

		if routeFound {
			ingressStatus.Status.ComponentRoutes = componentRoutes
			ingress := applyconfigv1.Ingress(ingressConfig.Name).WithStatus(ingressStatus.Status)
			if _, err := c.ingressClient.ApplyStatus(ctx, ingress, c.forceApply()); err != nil {
				return err
			}
		}
	}

	// delete secret by syncing an empty source
	if err := c.syncSecret(""); err != nil {
		return err
	}

	return nil
}
