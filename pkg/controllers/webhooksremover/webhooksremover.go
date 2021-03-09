package webhooksremover

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type webhooksRemoverController struct {
	authConfigClient configv1client.AuthenticationInterface
	authConfigLister configv1listers.AuthenticationLister
}

// NewWebhooksRemoverController creates a controller that removes the WebhookTokenAuthenticator
// configuration from the authentication.config object.
// This controller exists in case of a downgrade from OCP versions where this field
// is being set by this very operator. If left unset, this field would render the
// cluster unupgradable.
func NewWebhooksRemoverController(
	operatorClient v1helpers.OperatorClient,
	authConfigClient configv1client.AuthenticationInterface,
	authConfigInformer configv1informers.SharedInformerFactory,
	eventsRecorder events.Recorder,
) factory.Controller {
	c := webhooksRemoverController{
		authConfigClient: authConfigClient,
		authConfigLister: authConfigInformer.Config().V1().Authentications().Lister(),
	}

	return factory.New().
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		WithInformers(
			operatorClient.Informer(),
			authConfigInformer.Config().V1().Authentications().Informer(),
		).
		ToController("WebhooksRemover", eventsRecorder.WithComponentSuffix("webhooks-remover"))
}

func (c *webhooksRemoverController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	authConfig, err := c.authConfigLister.Get("cluster")
	if err != nil {
		return err
	}

	if authConfig.Spec.Type != configv1.AuthenticationTypeIntegratedOAuth && len(authConfig.Spec.Type) != 0 {
		// not using integrated openshift auth
		return nil
	}

	if authConfig.Spec.WebhookTokenAuthenticator == nil {
		return nil
	}

	authConfigCopy := authConfig.DeepCopy()
	authConfigCopy.Spec.WebhookTokenAuthenticator = nil

	_, err = c.authConfigClient.Update(ctx, authConfigCopy, v1.UpdateOptions{})
	return err
}
