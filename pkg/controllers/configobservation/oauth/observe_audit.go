package oauth

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func ObserveAudit(
	genericListers configobserver.Listers,
	recorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, _ []error) {
	somePath := []string{"oauthConfig", "auditProfile"}
	defer func() {
		ret = configobserver.Pruned(ret, somePath)
	}()

	listers := genericListers.(configobservation.Listers)
	errs := []error{}

	oauthConfig, err := listers.OAuthLister().Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warning("oauth.config.openshift.io/cluster: not found")
		return map[string]interface{}{}, []error{err}
	} else if err != nil {
		return existingConfig, []error{err}
	}

	observedAuditProfile := oauthConfig.Spec.Audit.Profile
	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedField(
		observedConfig,
		observedAuditProfile,
		somePath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	currentAuditProfile, _, err := unstructured.NestedString(
		existingConfig,
		somePath...,
	)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	if currentAuditProfile != string(observedAuditProfile) {
		recorder.Eventf(
			"ObserveAuditProfile",
			"AuditProfile changed from %s to %s",
			currentAuditProfile,
			observedAuditProfile,
		)
	}

	return observedConfig, errs
}
