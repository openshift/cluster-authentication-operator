package oauthapiserverpruner

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"
	apiregistrationv1informer "k8s.io/kube-aggregator/pkg/client/informers/externalversions/apiregistration/v1"
	apiregistrationv1lister "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"

	operatorclientinformers "github.com/openshift/client-go/operator/informers/externalversions"
	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	OAuthApiServerNsToRemove = "openshift-oauth-apiserver"
)

type oauthAPIServerPrunerController struct {
	apiServicesManagedByOAS []string

	namespaceClient corev1client.NamespaceInterface
	secretClient    corev1client.SecretInterface

	apiregistrationv1Lister apiregistrationv1lister.APIServiceLister
	authOperatorLister      operatorlistersv1.AuthenticationLister
	namespaceLister         corev1listers.NamespaceLister
}

// NewOAuthAPIServerPrunerController removes "openshift-oauth-apiserver" namespace.
//
// The namespace holds the OAuth API Server and all necessary resources that are valid only for 4.6+ clusters
// This controller is intended to clean up in case of a downgrade from 4.6 to 4.5.
func NewOAuthAPIServerPrunerController(
	name string,
	apiServicesManagedByOAS []string,
	kubeClient corev1client.CoreV1Interface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	authOperatorInformers operatorclientinformers.SharedInformerFactory,
	apiregistrationv1Informer apiregistrationv1informer.APIServiceInformer,
	eventRecorder events.Recorder) factory.Controller {

	authInformers := authOperatorInformers.Operator().V1().Authentications()

	c := &oauthAPIServerPrunerController{
		apiServicesManagedByOAS: apiServicesManagedByOAS,
		namespaceClient:         kubeClient.Namespaces(),
		secretClient:            kubeClient.Secrets(OAuthApiServerNsToRemove),
		apiregistrationv1Lister: apiregistrationv1Informer.Lister(),
		authOperatorLister:      authInformers.Lister(),
		namespaceLister:         kubeInformersForNamespaces.InformersFor("").Core().V1().Namespaces().Lister(),
	}

	controllerFactory := factory.New()
	controllerFactory.WithInformers(authInformers.Informer(), kubeInformersForNamespaces.InformersFor("").Core().V1().Namespaces().Informer(), apiregistrationv1Informer.Informer())
	controllerFactory.WithSync(c.sync)

	return controllerFactory.ToController(name, eventRecorder.WithComponentSuffix("oauth-apiserver-cleaner-controller"))
}

func (c *oauthAPIServerPrunerController) sync(ctx context.Context, _ factory.SyncContext) error {
	// check the ManagingOAuthAPIServer field
	operator, err := c.authOperatorLister.Get("cluster")
	if err != nil {
		return err
	}

	if operator.Status.ManagingOAuthAPIServer {
		klog.V(2).Info("waiting for ManagingOAuthAPIServer field to be set to false")
		return nil // we will be called again once the operator status changes
	}

	// be graceful and check if the API Services that were managed by CAO in 4.6 are now being managed by OAS-O
	for _, apiServiceName := range c.apiServicesManagedByOAS {
		managedByOAS, err := c.isAPIServiceMangedByOAS(apiServiceName)
		if err != nil {
			return err
		}
		if !managedByOAS {
			klog.V(2).Infof("waiting for the api service %s to be managed by OAS-O", apiServiceName)
			return nil // we will be called again once the api services change
		}
	}

	// remove the namespace
	if _, err := c.namespaceLister.Get(OAuthApiServerNsToRemove); err != nil {
		if errors.IsNotFound(err) {
			return nil // no-op the namespace was already removed
		}
		return err
	}
	if err := c.namespaceClient.Delete(ctx, OAuthApiServerNsToRemove, metav1.DeleteOptions{}); err != nil {
		return err
	}

	// remove the finalizer from the encryption config secrets (encryption-config ,encryption-config-REVISION)
	// otherwise the namespace won't be removed
	allSecrets, err := c.secretClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var finalizerDeletionErrs []error
	for _, secret := range allSecrets.Items {
		if finalizers := sets.NewString(secret.Finalizers...); finalizers.Has(secrets.EncryptionSecretFinalizer) {
			delete(finalizers, secrets.EncryptionSecretFinalizer)
			secret.Finalizers = finalizers.List()
			if _, err := c.secretClient.Update(ctx, &secret, metav1.UpdateOptions{}); err != nil {
				finalizerDeletionErrs = append(finalizerDeletionErrs, err)
			}
		}
	}
	return utilerrors.NewAggregate(finalizerDeletionErrs)
}

func (c *oauthAPIServerPrunerController) isAPIServiceMangedByOAS(apiServiceName string) (bool, error) {
	existingApiService, err := c.apiregistrationv1Lister.Get(apiServiceName)
	if err != nil {
		return false, err
	}

	// we don't check the "authentication.operator.openshift.io/managed" annotation because it is only set by CAO (4.6) to true.
	// there is no component that sets it back to false or removes it
	if existingApiService.Spec.Service != nil && existingApiService.Spec.Service.Namespace != OAuthApiServerNsToRemove {
		return true, nil
	}

	return false, nil
}
