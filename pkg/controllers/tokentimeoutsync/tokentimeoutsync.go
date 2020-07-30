package tokentimeoutsync

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"

	oauthv1 "github.com/openshift/api/oauth/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	oauthv1lister "github.com/openshift/client-go/oauth/listers/oauth/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

// tokenTimeoutSyncController synchronizes timeouts of existing OAuthAccessToken
// objects when this value changes in an OAuthClient or in OAuth/cluster TokenConfig
type tokenTimeoutSyncController struct {
	oauthConfigLister configv1lister.OAuthLister
	oauthClientLister oauthv1lister.OAuthClientLister
	accessTokens      oauthv1client.OAuthAccessTokenInterface

	lastSeenConfigTimeout time.Duration
	clientTimeouts        map[string]*time.Duration

	clientLocks sync.Map
}

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"OAuthConfigGetFailed",
	"OAuthClientListFailed",
	"TokenListFailed",
)

func NewTokenTimeoutSyncController(
	accessTokenClient oauthv1client.OAuthAccessTokenInterface,
	oauthInformers oauthinformer.SharedInformerFactory,
	configInformers configinformer.SharedInformerFactory,
	recorder events.Recorder,
) factory.Controller {
	c := &tokenTimeoutSyncController{
		accessTokens:      accessTokenClient,
		oauthConfigLister: configInformers.Config().V1().OAuths().Lister(),
		oauthClientLister: oauthInformers.Oauth().V1().OAuthClients().Lister(),

		// setting it to 0 should have no offect even on a first run since all
		// timeouts should be less than or equal to (now + tokenTimeout)
		lastSeenConfigTimeout: 0,
		clientTimeouts:        map[string]*time.Duration{},
	}

	return factory.New().WithInformersQueueKeyFunc(
		clusterObjToQueueKey, oauthInformers.Oauth().V1().OAuthClients().Informer(),
	).WithInformersQueueKeyFunc(
		clusterObjToQueueKey, configInformers.Config().V1().OAuths().Informer(),
	).WithSync(c.sync).ToController("TokenTimeoutSyncController", recorder.WithComponentSuffix("wellknown-ready-controller"))
}

func clusterObjToQueueKey(obj runtime.Object) string {
	metaObj := obj.(metav1.Object)
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if len(kind) == 0 { // OAuthClients don't seem to bear this information in the generic runtime object manner
		if _, ok := obj.(*oauthv1.OAuthClient); ok {
			kind = "OAuthClient"
		}
	}
	return fmt.Sprintf("%s/%s", kind, metaObj.GetName())
}

func (c *tokenTimeoutSyncController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	key := syncContext.QueueKey()

	resourceNamePair := strings.SplitN(key, "/", 2)
	if len(resourceNamePair) != 2 {
		return fmt.Errorf("can't process key: %s", key)
	}

	switch resourceNamePair[0] {
	case "OAuth":
		clientLock := c.lockSyncForKey(key)
		defer clientLock.Unlock()
		return c.syncGlobalConfig(ctx, syncContext)
	case "OAuthClient":
		configLock := c.lockSyncForKey(key)
		defer configLock.Unlock()
		return c.syncOAuthClient(ctx, syncContext, resourceNamePair[1])
	default:
		return fmt.Errorf("not processing kind: %s", resourceNamePair[0])
	}
}

func (c *tokenTimeoutSyncController) syncOAuthClient(ctx context.Context, syncContext factory.SyncContext, oauthClientName string) error {
	client, err := c.oauthClientLister.Get(oauthClientName)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.Errorf("OAuthClient %s not found, it was probably deleted", oauthClientName)
		}
		return err
	}

	oauthConfig, err := c.oauthConfigLister.Get("cluster")
	if err != nil {
		return err
	}

	var clientTimeout *time.Duration
	var observedTimeout time.Duration
	// requeue for this specific client in case there was an error processing a token
	defer func() {
		if err == nil {
			c.clientTimeouts[client.Name] = clientTimeout
		} else {
			// requeue to update the failed tokens
			syncContext.Queue().Add("OAuthClient/" + oauthClientName)
		}
	}()

	cachedTimeout := c.clientTimeouts[oauthClientName]
	if client.AccessTokenInactivityTimeoutSeconds == nil {
		if cachedTimeout == nil { // no change
			return nil
		}
		// the new config makes the client tokens use the global inactivity timeout
		observedTimeout = oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout.Duration
	} else {
		// client-specific timeout
		observedTimeout = time.Duration(*client.AccessTokenInactivityTimeoutSeconds) * time.Second
		if cachedTimeout != nil && observedTimeout == *cachedTimeout {
			return nil
		}
		clientTimeout = &observedTimeout
	}

	// the new timeout is greater than the previous
	if cachedTimeout != nil && *cachedTimeout != 0 && (observedTimeout > *cachedTimeout || observedTimeout == 0) {
		return nil
	}

	tokenList, err := c.accessTokens.List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("clientName", oauthClientName).String()})
	if err != nil {
		return err
	}

	var updateErr error
	for _, token := range tokenList.Items {
		tokenCopy := token.DeepCopy()
		if applyTimeout(tokenCopy, observedTimeout) {
			_, err = c.accessTokens.Update(ctx, tokenCopy, metav1.UpdateOptions{})
			if err != nil {
				// TODO: once we're sure only sha256 tokens appear in the API, print the token name here
				updateErr = fmt.Errorf("failed to update token")
				klog.Error(updateErr.Error())
			}
		}
	}

	return updateErr
}

func (c *tokenTimeoutSyncController) syncGlobalConfig(ctx context.Context, syncContext factory.SyncContext) error {
	oauthConfig, err := c.oauthConfigLister.Get("cluster")
	if err != nil {
		return err
	}

	var observedTimeout time.Duration
	if oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout != nil {
		observedTimeout = oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout.Duration
	} else {
		observedTimeout = 0
	}

	if observedTimeout != c.lastSeenConfigTimeout {
		// requeue for global config in case there are errors processing some tokens
		defer func() {
			if err == nil {
				// no errors -> cache the new global timeout value
				c.lastSeenConfigTimeout = observedTimeout
			} else {
				syncContext.Queue().Add("OAuth/cluster")
			}
		}()
	}

	if c.lastSeenConfigTimeout != 0 && (observedTimeout > c.lastSeenConfigTimeout || observedTimeout == 0) {
		return nil
	}

	tokenList, err := c.accessTokens.List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var updateErr error
	for _, t := range tokenList.Items {
		oauthClient, err := c.oauthClientLister.Get(t.ClientName)
		if err != nil {
			if errors.IsNotFound(err) {
				klog.Errorf("could not find client %q for a token", t.ClientName)
				continue
			}
			return err
		}

		if oauthClient.AccessTokenInactivityTimeoutSeconds != nil {
			// the client handles the timeouts itself
			continue
		}

		tokenCopy := t.DeepCopy()
		if applyTimeout(tokenCopy, observedTimeout) {
			_, err = c.accessTokens.Update(ctx, tokenCopy, metav1.UpdateOptions{})
			if err != nil {
				updateErr = fmt.Errorf("failed to update token")
				klog.Error(updateErr.Error())
			}
		}
	}

	return updateErr
}

// lockSyncFofKey locks sync for a given key so that only one sync per a given
// key runs at all times
func (c *tokenTimeoutSyncController) lockSyncForKey(key string) *sync.Mutex {
	// prepare a locked lock in case it's not yet in the map of client locks
	clientLock := &sync.Mutex{}
	clientLock.Lock()

	mapClientLock, ok := c.clientLocks.LoadOrStore(key, clientLock)
	actualLock := clientLock
	if ok {
		actualLock = mapClientLock.(*sync.Mutex)
		actualLock.Lock()
		clientLock.Unlock() // would it be GCed otherwise?
	}

	return actualLock
}

func (c *tokenTimeoutSyncController) getOAuthClientTimeout(clientName string) (*int32, error) {
	if _, _, err := serviceaccount.SplitUsername(clientName); err == nil {
		var saTimeout int32 = 0
		return &saTimeout, nil
	}

	tokenClient, err := c.oauthClientLister.Get(clientName)
	if err != nil {
		klog.V(4).Infof("token had clientName set to a non-existent oauth-client: %s", clientName)
		return nil, err
	}
	return tokenClient.AccessTokenInactivityTimeoutSeconds, nil

}

func applyTimeout(tokenCopy *oauthv1.OAuthAccessToken, timeout time.Duration) bool {
	// count a new timeout based on the current time
	newTimeout := int32((time.Now().Sub(tokenCopy.CreationTimestamp.Time) + timeout) / time.Second)
	if oldTimeout := tokenCopy.InactivityTimeoutSeconds; oldTimeout == 0 || newTimeout < oldTimeout {
		tokenCopy.InactivityTimeoutSeconds = newTimeout
		return true
	}

	return false
}
