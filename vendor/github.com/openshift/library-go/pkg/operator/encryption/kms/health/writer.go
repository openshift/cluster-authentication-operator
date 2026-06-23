package health

import (
	"context"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// NewEncryptionStatusWriterFunc builds the EncryptionStatusWriter for a target
// CR. The caller binds the concrete CR; this package only supplies the rest
// config and a reporterID. reporterID is a stable, per-node identifier the write
// path uses to claim ownership of its own entries; with server-side apply, pass
// it as the field manager.
type NewEncryptionStatusWriterFunc func(restConfig *rest.Config, reporterID string) (EncryptionStatusWriter, error)

// EncryptionStatusWriter is injected by the operator. The operator knows where
// to put it. Creating the status is the health reporter's concern.
type EncryptionStatusWriter func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error

// buildEncryptionStatus builds the KMSEncryptionStatusApplyConfiguration to be
// applied by the operator.
func buildEncryptionStatus(nodeName string, reports []pluginHealthReport) *applyoperatorv1.KMSEncryptionStatusApplyConfiguration {
	healthReports := make([]*applyoperatorv1.KMSPluginHealthReportApplyConfiguration, 0, len(reports))
	for _, r := range reports {
		hr := applyoperatorv1.KMSPluginHealthReport().
			WithNodeName(nodeName).
			WithKeyId(r.KeyID).
			WithStatus(mapStatus(r.Status)).
			WithLastCheckedTime(metav1.NewTime(r.LastChecked))

		// kekId/detail have MinLength=1; setting "" would fail validation.
		if r.KEKID != "" {
			hr = hr.WithKEKId(r.KEKID)
		}
		if r.Detail != "" {
			hr = hr.WithDetail(r.Detail)
		}

		healthReports = append(healthReports, hr)
	}

	return applyoperatorv1.KMSEncryptionStatus().WithHealthReports(healthReports...)
}

// mapStatus defaults to Error so an unknown value never becomes an empty,
// invalid enum.
func mapStatus(s string) operatorv1.KMSPluginHealthStatus {
	switch s {
	case statusHealthy:
		return operatorv1.KMSPluginHealthStatusHealthy
	case statusUnhealthy:
		return operatorv1.KMSPluginHealthStatusUnhealthy
	default:
		return operatorv1.KMSPluginHealthStatusError
	}
}
