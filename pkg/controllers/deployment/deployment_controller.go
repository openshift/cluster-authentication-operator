package deployment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"OAuthServerDeploymentAvailable",
	"OAuthServerDeploymentDegraded",
	"OAuthServerDeploymentProgressing",
	"OAuthServerIngressConfigDegraded",
	"OAuthServerProxyDegraded",
	"OAuthServerRouteDegraded",
)

type deploymentController struct {
	operatorClient v1helpers.OperatorClient

	deployments       appsv1client.DeploymentsGetter
	oauthClientClient oauthv1client.OAuthClientInterface
	auth              operatorv1client.AuthenticationsGetter

	configMapLister corev1listers.ConfigMapLister
	secretLister    corev1listers.SecretLister
	podsLister      corev1listers.PodLister
	routeLister     routev1lister.RouteLister
	ingressLister   configv1listers.IngressLister
	proxyLister     configv1listers.ProxyLister

	bootstrapUserDataGetter    bootstrap.BootstrapUserDataGetter
	bootstrapUserChangeRollOut bool
}

func NewDeploymentController(kubeInformersForTargetNamespace informers.SharedInformerFactory, routeInformer routeinformer.SharedInformerFactory, configInformers configinformer.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient, auth operatorv1client.AuthenticationsGetter, oauthClientClient oauthv1client.OAuthClientInterface, deployments appsv1client.DeploymentsGetter,
	bootstrapUserDataGetter bootstrap.BootstrapUserDataGetter,
	recorder events.Recorder) factory.Controller {
	c := &deploymentController{
		operatorClient:          operatorClient,
		oauthClientClient:       oauthClientClient,
		deployments:             deployments,
		auth:                    auth,
		configMapLister:         kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		secretLister:            kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		routeLister:             routeInformer.Route().V1().Routes().Lister(),
		podsLister:              kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		ingressLister:           configInformers.Config().V1().Ingresses().Lister(),
		proxyLister:             configInformers.Config().V1().Proxies().Lister(),
		bootstrapUserDataGetter: bootstrapUserDataGetter,
	}

	if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		c.bootstrapUserChangeRollOut = true
	} else {
		c.bootstrapUserChangeRollOut = userExists
	}

	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
		kubeInformersForTargetNamespace.Apps().V1().Deployments().Informer(),
		routeInformer.Route().V1().Routes().Informer(),
		configInformers.Config().V1().Authentications().Informer(),
		configInformers.Config().V1().Proxies().Informer(),
		configInformers.Config().V1().Ingresses().Informer(),
		operatorClient.Informer(),
	).ResyncEvery(30*time.Second).WithSync(c.sync).ToController("Deployment", recorder.WithComponentSuffix("deployment-controller"))
}

func (c *deploymentController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	operatorConfig, authConfigConditions := c.getAuthConfig(ctx)
	foundConditions = append(foundConditions, authConfigConditions...)

	ingress, ingressConditions := common.GetIngressConfig(c.ingressLister, "OAuthServerIngressConfig")
	foundConditions = append(foundConditions, ingressConditions...)

	route, routeConditions := c.getCanonicalRoute(ingress.Spec.Domain)
	foundConditions = append(foundConditions, routeConditions...)

	proxyConfig, proxyConditions := c.getProxyConfig()
	foundConditions = append(foundConditions, proxyConditions...)

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, c.ensureBootstrappedOAuthClients(ctx, "https://"+route.Spec.Host)...)
	}

	// resourceVersions serves to store versions of config resources so that we
	// can redeploy our payload should either change. We only omit the operator
	// config version, it would both cause redeploy loops (status updates cause
	// version change) and the relevant changes (logLevel, unsupportedConfigOverrides)
	// will cause a redeploy anyway
	// TODO move this hash from deployment meta to operatorConfig.status.generations.[...].hash
	resourceVersions := []string{}

	if len(proxyConfig.Name) > 0 {
		resourceVersions = append(resourceVersions, "proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion)
	}

	configResourceVersions, configResourceVersionsConditions := c.getConfigResourceVersions()
	foundConditions = append(foundConditions, configResourceVersionsConditions...)

	resourceVersions = append(resourceVersions, configResourceVersions...)

	// Determine whether the bootstrap user has been deleted so that
	// detail can be used in computing the deployment.
	if c.bootstrapUserChangeRollOut {
		if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
			klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		} else {
			c.bootstrapUserChangeRollOut = userExists
		}
	}

	if len(foundConditions) == 0 {
		// deployment, have RV of all resources
		expectedDeployment, deploymentConditions := getOAuthServerDeployment(operatorConfig, proxyConfig, c.bootstrapUserChangeRollOut, resourceVersions...)
		foundConditions = append(foundConditions, deploymentConditions...)

		if expectedDeployment != nil {
			deployment, _, err := resourceapply.ApplyDeployment(c.deployments, syncContext.Recorder(), expectedDeployment,
				resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorConfig.Status.Generations))

			if err != nil {
				foundConditions = append(foundConditions, operatorv1.OperatorCondition{
					Type:    "OAuthServerDeploymentDegraded",
					Status:  operatorv1.ConditionTrue,
					Reason:  "ApplyFailed",
					Message: fmt.Sprintf("Applying deployment of integrated OAuth server failed: %v", err),
				})
			} else {
				// check the deployment state, only record changed when the deployment is considered ready.
				foundConditions = append(foundConditions, common.CheckDeploymentReady(deployment, c.podsLister, "OAuthServerDeployment")...)
				if len(foundConditions) == 0 {
					if err := c.updateOperatorDeploymentInfo(ctx, syncContext, operatorConfig, deployment); err != nil {
						return err
					}
				}
			}

		}
	}

	// no matter what, check and set available.
	deployment, err := c.deployments.Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:    "OAuthServerDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "DeploymentAvailableReplicasCheckFailed",
			Message: err.Error(),
		})
	} else {
		if deployment.Status.AvailableReplicas > 0 {
			foundConditions = append(foundConditions, operatorv1.OperatorCondition{
				Type:    "OAuthServerDeploymentAvailable",
				Status:  operatorv1.ConditionTrue,
				Reason:  "AsExpected",
				Message: fmt.Sprintf("availableReplicas==%d", deployment.Status.AvailableReplicas),
			})
		} else {
			foundConditions = append(foundConditions, operatorv1.OperatorCondition{
				Type:    "OAuthServerDeploymentAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "NoReplicas",
				Message: "availableReplicas==0",
			})
		}
	}

	return common.UpdateControllerConditions(c.operatorClient, knownConditionNames, foundConditions)
}

func (c *deploymentController) getAuthConfig(ctx context.Context) (*operatorv1.Authentication, []operatorv1.OperatorCondition) {
	operatorConfig, err := c.auth.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    "OAuthServerDeploymentDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get cluster authentication config: %v", err),
			},
		}
	}
	return operatorConfig, nil
}

func (c *deploymentController) getCanonicalRoute(ingressConfigDomain string) (*routev1.Route, []operatorv1.OperatorCondition) {
	route, routeConditions := common.GetOAuthServerRoute(c.routeLister, "OAuthServerRoute")
	if len(routeConditions) > 0 {
		return nil, routeConditions
	}

	expectedHost := "oauth-openshift." + ingressConfigDomain
	if !common.RouteHasCanonicalHost(route, expectedHost) {
		msg := spew.Sdump(route.Status.Ingress)
		if len(route.Status.Ingress) == 0 {
			msg = "route status ingress is empty"
		}
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    "OAuthServerRouteDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "InvalidCanonicalHost",
				Message: fmt.Sprintf("Route is not available at canonical host %s: %+v", expectedHost, msg),
			},
		}
	}
	return route, nil
}

func (c *deploymentController) getProxyConfig() (*configv1.Proxy, []operatorv1.OperatorCondition) {
	proxyConfig, err := c.proxyLister.Get("cluster")
	if err != nil && !errors.IsNotFound(err) {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthServerProxyDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "GetFailed",
			Message: fmt.Sprintf("Unable to get cluster proxy configuration: %v", err),
		}}
	}
	if err != nil {
		klog.V(4).Infof("No proxy configuration found, defaulting to empty")
		return &configv1.Proxy{}, nil
	}
	return proxyConfig, nil
}

func (c *deploymentController) getConfigResourceVersions() ([]string, []operatorv1.OperatorCondition) {
	var configRVs []string

	configMaps, err := c.configMapLister.ConfigMaps("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthServerDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "ListFailed",
			Message: fmt.Sprintf("Unable to list configmaps in %q namespace: %v", "openshift-authentication", err),
		}}
	}
	for _, cm := range configMaps {
		if strings.HasPrefix(cm.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.Name+":"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secretLister.Secrets("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthServerDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "ListFailed",
			Message: fmt.Sprintf("Unable to list secrets in %q namespace: %v", "openshift-authentication", err),
		}}
	}
	for _, secret := range secrets {
		if strings.HasPrefix(secret.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.Name+":"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}

func randomBits(bits int) []byte {
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

func (c *deploymentController) ensureBootstrappedOAuthClients(ctx context.Context, masterPublicURL string) []operatorv1.OperatorCondition {
	browserClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-browser-client"},
		Secret:                base64.RawURLEncoding.EncodeToString(randomBits(256)),
		RespondWithChallenges: false,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenDisplayURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(ctx, c.oauthClientClient, browserClient); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "OAuthServerDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "GetFailed",
			Message: fmt.Sprintf("Unable to get %q bootstrapped OAuth client: %v", browserClient.Name, err),
		}}
	}

	cliClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-challenging-client"},
		Secret:                "",
		RespondWithChallenges: true,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenImplicitURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(ctx, c.oauthClientClient, cliClient); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "OAuthServerDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "GetFailed",
			Message: fmt.Sprintf("Unable to get %q bootstrapped CLI OAuth client: %v", browserClient.Name, err),
		}}
	}

	return nil
}

// updateOperatorDeploymentInfo updates the operator's Status .ReadyReplicas, .Generation and the
// .Generetions field with data about the oauth-server deployment
func (c *deploymentController) updateOperatorDeploymentInfo(
	ctx context.Context,
	syncContext factory.SyncContext,
	operatorConfig *operatorv1.Authentication,
	deployment *appsv1.Deployment,
) error {
	operatorStatusOutdated := operatorConfig.Status.ObservedGeneration != operatorConfig.Generation || operatorConfig.Status.ReadyReplicas != deployment.Status.UpdatedReplicas

	if operatorStatusOutdated {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			operatorConfig, _ := c.getAuthConfig(ctx)

			// make sure we record the changes to the deployment
			// if this fail, lets resync, this should not fail
			resourcemerge.SetDeploymentGeneration(&operatorConfig.Status.Generations, deployment)
			operatorConfig.Status.ObservedGeneration = operatorConfig.Generation
			operatorConfig.Status.ReadyReplicas = deployment.Status.UpdatedReplicas

			_, err := c.auth.Authentications().UpdateStatus(ctx, operatorConfig, metav1.UpdateOptions{})
			return err
		}); err != nil {
			syncContext.Recorder().Warningf("AuthenticationUpdateStatusFailed", "Failed to update authentication operator status: %v", err)
			return err
		}
	}
	return nil
}
