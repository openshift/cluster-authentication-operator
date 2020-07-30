package tokentimeoutsync

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	fakeoauth "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	oauthv1lister "github.com/openshift/client-go/oauth/listers/oauth/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_tokenTimeoutSyncController_sync(t *testing.T) {
	type args struct {
		ctx               context.Context
		controllerContext factory.SyncContext
	}
	tests := []struct {
		name                    string
		initGlobalTimeout       time.Duration
		newGlobalTimeout        time.Duration
		initClientTimeout       *time.Duration
		newClientTimeout        *int32
		initTokenTimeout        int32
		tokenCreationTimestamp  *metav1.Time
		expectedTokenInactivity int32
		expectedUpdate          bool
		wantErr                 bool
	}{
		{
			name:                    "update global to lower number",
			initGlobalTimeout:       0,
			newGlobalTimeout:        500 * time.Second,
			initTokenTimeout:        0,
			expectedTokenInactivity: 500,
			expectedUpdate:          true,
		},
		{
			name:                    "update global to lower number, don't update token",
			initGlobalTimeout:       700,
			newGlobalTimeout:        500 * time.Second,
			initTokenTimeout:        400,
			expectedTokenInactivity: 400,
		},
		{
			name:                    "update client to lower number",
			initGlobalTimeout:       0,
			newGlobalTimeout:        0,
			initClientTimeout:       pduration(600),
			newClientTimeout:        pint32(400),
			initTokenTimeout:        550,
			expectedTokenInactivity: 400,
			expectedUpdate:          true,
		},
		{
			name:                    "update client to lower number, don't update token",
			initGlobalTimeout:       0,
			newGlobalTimeout:        0,
			initClientTimeout:       pduration(600),
			newClientTimeout:        pint32(400),
			initTokenTimeout:        250,
			expectedTokenInactivity: 250,
		},
		{
			name:                    "update client to use global which is a lower number",
			initGlobalTimeout:       0,
			newGlobalTimeout:        500 * time.Second,
			initClientTimeout:       pduration(600),
			newClientTimeout:        nil,
			initTokenTimeout:        530,
			expectedTokenInactivity: 500,
			expectedUpdate:          true,
		},
		{
			name:                    "update global to zero",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        0,
			initClientTimeout:       nil,
			newClientTimeout:        nil,
			initTokenTimeout:        220,
			expectedTokenInactivity: 220,
			expectedUpdate:          false,
		},
		{
			name:                    "update client to zero",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        500 * time.Second,
			initClientTimeout:       pduration(500),
			newClientTimeout:        pint32(0),
			initTokenTimeout:        30,
			expectedTokenInactivity: 0,
			expectedUpdate:          false,
		},
		{
			name:              "do nothing = everything's the same",
			initGlobalTimeout: 500 * time.Second,
			newGlobalTimeout:  500 * time.Second,
			initClientTimeout: pduration(500),
			newClientTimeout:  pint32(500),
			initTokenTimeout:  820,
		},
		{
			name:                    "do nothing = global timeout is raised",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        600 * time.Second,
			initClientTimeout:       nil,
			newClientTimeout:        nil,
			expectedTokenInactivity: 500,
			initTokenTimeout:        2530,
		},
		{
			name:                    "do nothing = client timeout is raised",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        500 * time.Second,
			initClientTimeout:       pduration(400),
			newClientTimeout:        pint32(600),
			expectedTokenInactivity: 400,
			initTokenTimeout:        2530,
		},
		{
			name:                    "update token from the past by client timeout update",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        500 * time.Second,
			initClientTimeout:       pduration(600),
			newClientTimeout:        pint32(400),
			expectedTokenInactivity: 24*3600 + 400,
			initTokenTimeout:        24*3600 + 500,
			tokenCreationTimestamp:  &metav1.Time{Time: time.Now().AddDate(0, 0, -1)},
			expectedUpdate:          true,
		},
		{
			name:                    "update token from the past by global timeout update",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        300 * time.Second,
			expectedTokenInactivity: 24*3600 + 300,
			initTokenTimeout:        24*3600 + 500,
			tokenCreationTimestamp:  &metav1.Time{Time: time.Now().AddDate(0, 0, -1)},
			expectedUpdate:          true,
		},
		{
			name:                    "don't update token from the past by client timeout update",
			initGlobalTimeout:       500 * time.Second,
			newGlobalTimeout:        500 * time.Second,
			initClientTimeout:       pduration(1200),
			newClientTimeout:        pint32(850),
			expectedTokenInactivity: 24*3600 + 500,
			initTokenTimeout:        24*3600 + 500,
			tokenCreationTimestamp:  &metav1.Time{Time: time.Now().AddDate(0, 0, -1)},
		},
		{
			name:                    "don't update token from the past by global timeout update",
			initGlobalTimeout:       800 * time.Second,
			newGlobalTimeout:        350 * time.Second,
			expectedTokenInactivity: 24*3600 + 300,
			initTokenTimeout:        24*3600 + 300,
			tokenCreationTimestamp:  &metav1.Time{Time: time.Now().AddDate(0, 0, -1)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oauthIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := oauthIndexer.Add(&configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenInactivityTimeout: &metav1.Duration{Duration: tt.newGlobalTimeout},
					},
				},
			}); err != nil {
				t.Fatal(err)
			}
			oauthClientIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := oauthClientIndexer.Add(&oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testclient",
				},
				AccessTokenInactivityTimeoutSeconds: tt.newClientTimeout,
			}); err != nil {
				t.Fatal(err)
			}

			creationTimestamp := metav1.Time{Time: time.Now()}
			if tt.tokenCreationTimestamp != nil {
				creationTimestamp = *tt.tokenCreationTimestamp
			}

			fakeOAuthClient := fakeoauth.NewSimpleClientset(&oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "sometoken",
					CreationTimestamp: creationTimestamp,
				},
				ClientName:               "testclient",
				InactivityTimeoutSeconds: tt.initTokenTimeout,
			})

			oauthConfigLister := configv1lister.NewOAuthLister(oauthIndexer)
			oauthClientLister := oauthv1lister.NewOAuthClientLister(oauthClientIndexer)

			c := &tokenTimeoutSyncController{
				oauthConfigLister:     oauthConfigLister,
				oauthClientLister:     oauthClientLister,
				accessTokens:          fakeOAuthClient.OauthV1().OAuthAccessTokens(),
				lastSeenConfigTimeout: tt.initGlobalTimeout,
				clientTimeouts: map[string]*time.Duration{
					"testclient": tt.initClientTimeout,
				},
			}

			queueKey := "OAuthClient/testclient"
			if tt.initGlobalTimeout != tt.newGlobalTimeout {
				queueKey = "OAuth/cluster"
			}
			if err := c.sync(context.TODO(), newTestSyncContext(queueKey)); (err != nil) != tt.wantErr {
				t.Errorf("tokenTimeoutSyncController.sync() error = %v, wantErr %v", err, tt.wantErr)
			}

			var updateFound bool
			for _, a := range fakeOAuthClient.Actions() {
				if a.GetVerb() == "update" && a.GetResource().Resource == "oauthaccesstokens" {
					updateFound = true
					tok := a.(clienttesting.UpdateAction).GetObject().(*oauthv1.OAuthAccessToken)
					if tok.InactivityTimeoutSeconds > (tt.expectedTokenInactivity + 5) {
						t.Fatalf("expected the token timeout to be within (%d, %d), but it's %d", tt.expectedTokenInactivity, tt.expectedTokenInactivity+5, tok.InactivityTimeoutSeconds)
					}
					break
				}
			}
			if tt.expectedUpdate != updateFound {
				t.Fatalf("expected token update: %v, but got %v instead; actions:: %v", tt.expectedUpdate, updateFound, fakeOAuthClient.Actions())
			}
		})
	}
}

func pint32(i int32) *int32 { return &i }

func pduration(i int32) *time.Duration {
	d := time.Duration(i) * time.Second
	return &d
}

type testSyncContext struct {
	queueKey      string
	eventRecorder events.Recorder
}

func (c testSyncContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (c testSyncContext) QueueKey() string {
	return c.queueKey
}

func (c testSyncContext) Recorder() events.Recorder {
	return c.eventRecorder
}

func newTestSyncContext(queueKey string) factory.SyncContext {
	return testSyncContext{
		queueKey:      queueKey,
		eventRecorder: events.NewInMemoryRecorder("test"),
	}
}
