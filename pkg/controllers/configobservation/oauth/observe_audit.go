package oauth

import (
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

var (
	ServerArgumentsPath = []string{
		"serverArguments",
	}
	auditOptionsArgs = map[string]interface{}{
		"audit-log-path":      []interface{}{"/var/log/oauth-server/audit.log"},
		"audit-log-format":    []interface{}{"json"},
		"audit-log-maxsize":   []interface{}{"100"},
		"audit-log-maxbackup": []interface{}{"10"},
		"audit-policy-file":   []interface{}{"/var/run/configmaps/audit/audit.yaml"},
	}
)

func GetOAuthServerArgumentsRaw(operatorConfig *runtime.RawExtension) (map[string]interface{}, error) {
	oauthServerObservedConfig, err := common.UnstructuredConfigFrom(
		operatorConfig.Raw,
		configobservation.OAuthServerConfigPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to grab the operator config: %w", err)
	}

	configDeserialized := new(struct {
		Args map[string]interface{} `json:"serverArguments"`
	})
	if err := json.Unmarshal(oauthServerObservedConfig, &configDeserialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the observedConfig: %v", err)
	}

	return configDeserialized.Args, nil
}


func ObserveAudit(
	genericListers configobserver.Listers,
	recorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, ServerArgumentsPath)
	}()

	listers := genericListers.(configobservation.Listers)
	var errs []error

	oauthConfig, err := listers.OAuthLister().Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warning("oauth.config.openshift.io/cluster: not found")
		oauthConfig = new(configv1.OAuth)
		klog.V(2).Info("xxx there is no oauth")
	} else if err != nil {
		klog.V(2).Info("xxx err on get oauth")
		return existingConfig, []error{fmt.Errorf(
			"xxx get oauth.config.openshift.io/cluster: %w",
			err,
		)}
	}

	observedConfig := map[string]interface{}{}
	observedAuditProfile := oauthConfig.Spec.Audit.Profile
	if observedAuditProfile != configv1.OAuthAuditProfileNone {
		if err := unstructured.SetNestedField(
			observedConfig,
			auditOptionsArgs,
			ServerArgumentsPath...,
		); err != nil {
			klog.V(2).Info("xxx err on adding nested fields")
			return existingConfig, append(errs, fmt.Errorf(
				"xxx set nested field (%s) for profile (%s): %w",
				strings.Join(ServerArgumentsPath, "/"),
				observedAuditProfile,
				err,
			))
		}
	}

	currentAuditProfile, _, err := unstructured.NestedFieldCopy(
		existingConfig,
		ServerArgumentsPath...,
	)
	if err != nil {
		klog.V(2).Info("xxx err on getting currrent stuff")
		return existingConfig, append(errs, err)
	}

	if !equality.Semantic.DeepEqual(currentAuditProfile, auditOptionsArgs) {
		recorder.Eventf(
			"ObserveAuditProfile",
			"AuditProfile changed from '%s' to '%s'",
			currentAuditProfile,
			auditOptionsArgs,
		)
		klog.V(2).Info("xxx state change")
	}

	klog.V(2).Infof("xxx observedConfig: %+v", observedConfig)

	return observedConfig, errs
}
