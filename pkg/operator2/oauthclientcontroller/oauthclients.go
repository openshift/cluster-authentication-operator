package oauthclientcontroller

/* ---- this is just old code, needs rework
import (
	"crypto/rand"
	"encoding/base64"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"

	oauthv1 "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)



const browserClientSecretByteLen = 32

func defaultBrowserOAuthClient(route *routev1.Route) *oauthv1.OAuthClient {
	return &oauthv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: authoputil.OAuthBrowserClientName,
		},
		GrantMethod: oauthv1.GrantHandlerAuto,
		Secret:      authoputil.RandomString(browserClientSecretByteLen),
	}
}

func defaultChallengingOAuthClient(route *routev1.Route) *oauthv1.OAuthClient {
	return &oauthv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: authoputil.OAuthChallengingClientName,
		},
		GrantMethod:           oauthv1.GrantHandlerAuto,
		RespondWithChallenges: true,
	}
}

func (c *oauthClientsController) ensureBrowserOAuthClient(current *oauthv1.OAuthClient, route *routev1.Route) error {
	defaultBrowserClient := defaultBrowserOAuthClient(route)

	// secret is set properly, don't try to change it
	if current != nil && len(current.Secret) == browserClientSecretByteLen {
		defaultBrowserClient.Secret = current.Secret
	}

	_, _, err := ApplyOAuthClient(c.oauthClientGetter, nil, defaultBrowserClient)
	return err
}

func (c *oauthClientsController) ensureChallengingOAuthClient(route *routev1.Route) error {
	_, _, err := ApplyOAuthClient(c.oauthClientGetter, nil, defaultChallengingOAuthClient(route))
	return err
}

// ApplyOAuthClient merges objectmeta. It returns the final Object, whether any change as made, and an error
func ApplyOAuthClient(
	client oauthclient.OAuthClientsGetter,
	recorder events.Recorder,
	required *oauthv1.OAuthClient,
) (*oauthv1.OAuthClient, bool, error) {
	existing, err := client.OAuthClients().Get(required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.OAuthClients().Create(required)
		// resourceapply.reportCreateEvent(recorder, actual, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	contentSame := equality.Semantic.DeepEqual(existingCopy, required)
	if contentSame && !*modified {
		return existingCopy, false, nil
	}

	objectMeta := existingCopy.ObjectMeta.DeepCopy()
	existingCopy = required.DeepCopy()
	existingCopy.ObjectMeta = *objectMeta

	if klog.V(4) {
		klog.Infof("OAuthClient %q changes: %v", required.Name, resourceapply.JSONPatch(existing, existingCopy))
	}

	actual, err := client.OAuthClients().Update(existingCopy)
	// reportUpdateEvent(recorder, required, err)

	return actual, true, err
}

// ensureBootstrappedOAuthClients creates or updates the bootstrap oauth clients that openshift relies upon.
func (c *oauthClientsController) ensureBootstrappedOAuthClients(masterPublicURL string) error {
	browserClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-browser-client"},
		Secret:                random256BitsString(),
		RespondWithChallenges: false,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenDisplayURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(c.oauthClientClient, browserClient); err != nil {
		return err
	}

	cliClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-challenging-client"},
		Secret:                "",
		RespondWithChallenges: true,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenImplicitURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(c.oauthClientClient, cliClient); err != nil {
		return err
	}

	return nil
}

func ensureOAuthClient(oauthClients oauthclient.OAuthClientInterface, client oauthv1.OAuthClient) error {
	_, err := oauthClients.Create(&client)
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := oauthClients.Get(client.Name, metav1.GetOptions{})
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

		_, err = oauthClients.Update(existingCopy)
		return err
	})
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

// RandomBitsString returns a random string with at least the requested bits of entropy.
// It uses RawURLEncoding to ensure we do not get / characters or trailing ='s.
func randomBitsString(bits int) string {
	return base64.RawURLEncoding.EncodeToString(randomBits(bits))
}

// Random256BitsString is a convenience function for calling RandomBitsString(256).
// Callers that need a random string should use this function unless they have a
// very good reason to need a different amount of entropy.
func random256BitsString() string {
	// 32 bytes (256 bits) = 43 base64-encoded characters
	return randomBitsString(256)
}
*/
