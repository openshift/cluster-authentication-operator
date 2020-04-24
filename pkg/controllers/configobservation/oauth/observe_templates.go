package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/datasync"
)

func ObserveTemplates(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	templatesPath := []string{"oauthConfig", "templates"}
	defer func() {
		ret = configobserver.Pruned(ret, templatesPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs = []error{}

	existingTemplates, _, err := unstructured.NestedFieldCopy(existingConfig, templatesPath...)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	oauthConfig, err := listers.OAuthLister.Get("cluster")
	if errors.IsNotFound(err) {
		// use the defauls for the platform set by `convertTemplatesWithBranding`
		oauthConfig = &configv1.OAuth{}
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	templates, syncData, err := convertTemplatesWithBranding(listers.ConfigMapLister, &oauthConfig.Spec.Templates)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	var observedTemplates interface{}
	if templates != nil {
		convertedBytes, err := json.Marshal(templates)
		if err != nil {
			return existingConfig, append(errs, err)
		}

		if err := json.NewDecoder(bytes.NewBuffer(convertedBytes)).Decode(&observedTemplates); err != nil {
			return existingConfig, append(errs, fmt.Errorf("decode of observed config failed with error: %v", err))
		}

		if err := unstructured.SetNestedField(observedConfig, observedTemplates, templatesPath...); err != nil {
			return existingConfig, append(errs, err)
		}
	}

	if !equality.Semantic.DeepEqual(existingTemplates, observedTemplates) {
		recorder.Eventf("ObserveTemplates", "templates changed to %q", observedTemplates)
	}

	syncTemplateSecrets(listers.ResourceSyncer(), syncData)

	return observedConfig, errs
}

func syncTemplateSecrets(syncer resourcesynccontroller.ResourceSyncer, syncData map[string]string) {
	// we need to go through each key to remove synced secrets that no longer should be synced
	srcName := syncData[configv1.LoginTemplateKey]
	datasync.SyncConfigOrDie(syncer.SyncSecret, "v4-0-config-user-template-login", srcName)

	srcName = syncData[configv1.ProviderSelectionTemplateKey]
	datasync.SyncConfigOrDie(syncer.SyncSecret, "v4-0-config-user-template-provider-selection", srcName)

	srcName = syncData[configv1.ErrorsTemplateKey]
	datasync.SyncConfigOrDie(syncer.SyncSecret, "v4-0-config-user-template-error", srcName)
}
