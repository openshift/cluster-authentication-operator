package oldtokensscraper

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	oauthv1 "github.com/openshift/api/oauth/v1"
	oauthlistersv1 "github.com/openshift/client-go/oauth/listers/oauth/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestOldTokensScraperSync(t *testing.T) {
	tests := []struct {
		name                       string
		accessTokensNames          []string
		authorizeTokensNames       []string
		expectedOldAccessTokens    uint64
		expectedOldAuthorizeTokens uint64
		wantErr                    bool
	}{
		{
			name: "no tokens",
		},
		{
			name:                       "no old-format accesstokens",
			accessTokensNames:          []string{"sha256~token1", "sha256~token2"},
			authorizeTokensNames:       []string{"sha256~token1", "oldtoken", "sha256~token2", "anotheroldtoken"},
			expectedOldAuthorizeTokens: 2,
		},
		{
			name:                    "no old-format authorize tokens",
			accessTokensNames:       []string{"sha256~token1", "sha256~token2", "realloldtoken"},
			authorizeTokensNames:    []string{"sha256~token1", "sha256~token2"},
			expectedOldAccessTokens: 1,
		},
		{
			name:                 "no old-format tokens",
			accessTokensNames:    []string{"sha256~token1", "sha256~token2", "sha256~something", "sha256~somethingelse"},
			authorizeTokensNames: []string{"sha256~token1", "sha256~token2"},
		},
		{
			name:                       "both access and authorize old-format tokens",
			accessTokensNames:          []string{"sha256~token1", "veryoldtoken", "dinosaurus", "sha256~token2", "sha256~something", "cyberman", "sha256~somethingelse"},
			authorizeTokensNames:       []string{"ancientrelic", "sha256~token1", "sha256~token2", "yesterdaysnewspaper"},
			expectedOldAccessTokens:    3,
			expectedOldAuthorizeTokens: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCtx := context.Background()

			authorizeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, tok := range tt.authorizeTokensNames {
				err := authorizeIndexer.Add(&oauthv1.OAuthAuthorizeToken{
					ObjectMeta: metav1.ObjectMeta{Name: tok},
				})
				require.NoError(t, err)
			}

			accessIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, tok := range tt.accessTokensNames {
				err := accessIndexer.Add(&oauthv1.OAuthAccessToken{
					ObjectMeta: metav1.ObjectMeta{Name: tok},
				})
				require.NoError(t, err)
			}

			s := &oldTokensScraper{
				oauthAuthorizeTokensLister: oauthlistersv1.NewOAuthAuthorizeTokenLister(authorizeIndexer),
				oauthAccessTokensLister:    oauthlistersv1.NewOAuthAccessTokenLister(accessIndexer),
			}

			if err := s.sync(testCtx, factory.NewSyncContext("", events.NewInMemoryRecorder("test"))); (err != nil) != tt.wantErr {
				t.Errorf("oldTokensScraper.sync() error = %v, wantErr %v", err, tt.wantErr)
			}

			wantOut := fmt.Sprintf(`
# HELP openshift_authentication_operator_old_accesstokens [ALPHA] Counts the number of access tokens that do not use the new hashed names
# TYPE openshift_authentication_operator_old_accesstokens gauge
openshift_authentication_operator_old_accesstokens %d
# HELP openshift_authentication_operator_old_authorizetokens [ALPHA] Counts the number of authorize tokens that do not use the new hashed names
# TYPE openshift_authentication_operator_old_authorizetokens gauge
openshift_authentication_operator_old_authorizetokens %d
			`, tt.expectedOldAccessTokens, tt.expectedOldAuthorizeTokens)
			if err := testutil.GatherAndCompare(
				legacyregistry.DefaultGatherer,
				strings.NewReader(wantOut),
				"openshift_authentication_operator_old_authorizetokens",
				"openshift_authentication_operator_old_accesstokens",
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}
