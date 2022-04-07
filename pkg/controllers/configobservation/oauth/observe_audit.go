package oauth

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

var (
	serverArgumentsPath = []string{
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

func ObserveAudit(
	genericListers configobserver.Listers,
	recorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, serverArgumentsPath)
	}()

	listers := genericListers.(configobservation.Listers)
	var errs []error

	apiServer, err := listers.APIServerLister().Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warning("config.openshift.io/v1/cluster: not found")
	} else if err != nil {
		return existingConfig, append(errs, fmt.Errorf(
			"failed to get oauth.config.openshift.io/cluster: %w",
			err,
		))
	}

	var observedAuditProfile configv1.AuditProfileType
	if apiServer != nil {
		observedAuditProfile = apiServer.Spec.Audit.Profile
	}

	observedConfig := map[string]interface{}{}
	if observedAuditProfile != configv1.NoneAuditProfileType {
		if err := unstructured.SetNestedField(
			observedConfig,
			auditOptionsArgs,
			serverArgumentsPath...,
		); err != nil {
			return existingConfig, append(errs, fmt.Errorf(
				"set nested field (%s) for profile (%s): %w",
				strings.Join(serverArgumentsPath, "/"),
				observedAuditProfile,
				err,
			))
		}
	}

	currentAuditProfile, _, err := unstructured.NestedFieldCopy(
		existingConfig,
		serverArgumentsPath...,
	)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	if !equality.Semantic.DeepEqual(currentAuditProfile, auditOptionsArgs) {
		recorder.Eventf(
			"ObserveAuditProfile",
			"AuditProfile changed from '%s' to '%s'",
			currentAuditProfile,
			auditOptionsArgs,
		)
	}

	return observedConfig, errs
}
