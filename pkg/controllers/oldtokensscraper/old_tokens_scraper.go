package oldtokensscraper

import (
	"context"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"

	oauthv1informers "github.com/openshift/client-go/oauth/informers/externalversions/oauth/v1"
	oauthv1listers "github.com/openshift/client-go/oauth/listers/oauth/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

type oldTokensScraper struct {
	oauthAccessTokensLister    oauthv1listers.OAuthAccessTokenLister
	oauthAuthorizeTokensLister oauthv1listers.OAuthAuthorizeTokenLister
}

var (
	oldAccessTokensTotal = metrics.NewGauge(
		&metrics.GaugeOpts{
			Subsystem: "openshift_authentication_operator",
			Name:      "old_accesstokens",
			Help:      "Counts the number of access tokens that do not use the new hashed names",
		},
	)

	oldAuthorizeTokensTotal = metrics.NewGauge(
		&metrics.GaugeOpts{
			Subsystem: "openshift_authentication_operator",
			Name:      "old_authorizetokens",
			Help:      "Counts the number of authorize tokens that do not use the new hashed names",
		},
	)
)

func init() {
	legacyregistry.MustRegister(oldAuthorizeTokensTotal)
	legacyregistry.MustRegister(oldAccessTokensTotal)
}

func NewOldTokensScraper(
	oauthInformers oauthv1informers.Interface,
	eventsRecorder events.Recorder,
) factory.Controller {
	s := &oldTokensScraper{
		oauthAuthorizeTokensLister: oauthInformers.OAuthAuthorizeTokens().Lister(),
		oauthAccessTokensLister:    oauthInformers.OAuthAccessTokens().Lister(),
	}

	return factory.New().
		ResyncEvery(1*time.Minute).
		WithSync(s.sync).
		WithBareInformers( // ignore any events and run on a simple once-per-minute basis
			oauthInformers.OAuthAuthorizeTokens().Informer(),
			oauthInformers.OAuthAccessTokens().Informer(),
		).
		ToController("OldTokensScraper", eventsRecorder.WithComponentSuffix("old-tokens-scraper"))
}

func (s *oldTokensScraper) sync(ctx context.Context, _ factory.SyncContext) error {
	const hashPrefix = "sha256~"
	var oldAuthorize, oldAccess uint64

	authorizeTokens, err := s.oauthAuthorizeTokensLister.List(labels.Everything())
	if err != nil {
		return err
	}

	accessTokens, err := s.oauthAccessTokensLister.List(labels.Everything())
	if err != nil {
		return err
	}

	for _, t := range authorizeTokens {
		if !strings.HasPrefix(t.GetName(), hashPrefix) {
			oldAuthorize++
		}
	}
	oldAuthorizeTokensTotal.Set(float64(oldAuthorize))

	for _, t := range accessTokens {
		if !strings.HasPrefix(t.GetName(), hashPrefix) {
			oldAccess++
		}
	}
	oldAccessTokensTotal.Set(float64(oldAccess))

	return nil
}
