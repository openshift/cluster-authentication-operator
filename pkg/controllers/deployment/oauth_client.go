package deployment

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	oauthv1 "github.com/openshift/api/oauth/v1"

	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
)

func ensureOAuthClient(ctx context.Context, oauthClients oauthclient.OAuthClientInterface, client oauthv1.OAuthClient) error {
	_, err := oauthClients.Create(ctx, &client, metav1.CreateOptions{})
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := oauthClients.Get(ctx, client.Name, metav1.GetOptions{})
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

		_, err = oauthClients.Update(ctx, existingCopy, metav1.UpdateOptions{})
		return err
	})
}
