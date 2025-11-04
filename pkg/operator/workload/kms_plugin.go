package workload

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

const (
	// KMSCredentialsSecretName is the name of the secret created by Cloud Credential Operator
	// containing AWS credentials for the KMS plugin
	KMSCredentialsSecretName = "kms-credentials"

	// DefaultKMSPluginImage is the fallback image if KMS_PLUGIN_IMAGE is not set
	DefaultKMSPluginImage = "quay.io/fmissi/aws-kms-plugin:0.1.0"
)

// getKMSEncryptionConfig checks if KMS encryption is enabled and returns the configuration
// Returns:
//   - kmsConfig: the KMS configuration if enabled, nil otherwise
//   - enabled: true if KMS encryption is enabled
//   - error: any error encountered while reading the config
func getKMSEncryptionConfig(ctx context.Context, apiserverLister configv1listers.APIServerLister) (*configv1.KMSConfig, bool, error) {
	apiserver, err := apiserverLister.Get("cluster")
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Info("APIServer config.openshift.io/cluster not found, KMS encryption not enabled")
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get APIServer config: %w", err)
	}

	// Check if encryption is configured
	if apiserver.Spec.Encryption.Type != configv1.EncryptionTypeKMS {
		klog.V(4).Infof("Encryption type is %q, not KMS - skipping KMS plugin injection", apiserver.Spec.Encryption.Type)
		return nil, false, nil
	}

	// KMS type is set, must have KMS config
	if apiserver.Spec.Encryption.KMS == nil {
		return nil, false, fmt.Errorf("encryption type is KMS but kms config is nil")
	}

	klog.Infof("KMS encryption enabled with type=%s, region=%s, keyARN=%s",
		apiserver.Spec.Encryption.KMS.Type,
		apiserver.Spec.Encryption.KMS.AWS.Region,
		apiserver.Spec.Encryption.KMS.AWS.KeyARN)

	return apiserver.Spec.Encryption.KMS, true, nil
}

// checkCredentialsSecret verifies that the KMS credentials secret exists
// This secret is created by Cloud Credential Operator based on CredentialsRequest
func checkCredentialsSecret(secretLister corev1listers.SecretLister, namespace string) (bool, error) {
	secret, err := secretLister.Secrets(namespace).Get(KMSCredentialsSecretName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(2).Infof("KMS credentials secret %s/%s not found - waiting for Cloud Credential Operator to create it",
				namespace, KMSCredentialsSecretName)
			return false, nil
		}
		return false, fmt.Errorf("failed to get KMS credentials secret: %w", err)
	}

	// Verify the secret has the expected data
	if secret.Data == nil || len(secret.Data["credentials"]) == 0 {
		return false, fmt.Errorf("KMS credentials secret %s/%s exists but is empty", namespace, KMSCredentialsSecretName)
	}

	klog.V(4).Infof("KMS credentials secret %s/%s exists and is valid", namespace, KMSCredentialsSecretName)
	return true, nil
}

// injectKMSPlugin adds the KMS plugin sidecar container to the openshift-apiserver deployment
// if KMS encryption is enabled in the cluster APIServer config
//
// Unlike kube-apiserver, openshift-apiserver runs as a regular Deployment without hostNetwork,
// so it cannot access IMDS directly. Instead, it uses credentials from a secret created by CCO.
func injectKMSPlugin(
	ctx context.Context,
	podSpec *corev1.PodSpec,
	apiserverLister configv1listers.APIServerLister,
	secretLister corev1listers.SecretLister,
	namespace string,
	kmsPluginImage string,
) error {
	// Check if KMS encryption is enabled
	kmsConfig, enabled, err := getKMSEncryptionConfig(ctx, apiserverLister)
	if err != nil {
		return fmt.Errorf("failed to check KMS encryption config: %w", err)
	}

	if !enabled {
		klog.V(4).Info("KMS encryption not enabled, skipping sidecar injection")
		return nil
	}

	// Verify credentials secret exists
	// This is created by Cloud Credential Operator based on CredentialsRequest
	secretExists, err := checkCredentialsSecret(secretLister, namespace)
	if err != nil {
		return fmt.Errorf("failed to check KMS credentials secret: %w", err)
	}

	if !secretExists {
		klog.Warningf("KMS encryption enabled but credentials secret not ready - skipping injection (will retry on next sync)")
		// Return nil (not error) so the deployment can still be created
		// The controller will retry when the secret is created
		return nil
	}

	// Validate the image is set
	if kmsPluginImage == "" {
		kmsPluginImage = DefaultKMSPluginImage
	}

	klog.Infof("Injecting KMS plugin sidecar container (image: %s)", kmsPluginImage)

	// Create container config for openshift-apiserver
	// openshift-apiserver is a Deployment without hostNetwork, so it needs credentials from a secret
	containerConfig := &kms.ContainerConfig{
		Image:                 kmsPluginImage,
		UseHostNetwork:        false, // Deployment without hostNetwork
		CredentialsSecretName: KMSCredentialsSecretName,
		KMSConfig:             kmsConfig,
	}

	// Inject the KMS plugin sidecar container and volumes into the pod spec
	// Use emptyDir for socket volume (not hostPath like static pods)
	if err := kms.AddKMSPluginToPodSpec(podSpec, kmsConfig, containerConfig, false); err != nil {
		return fmt.Errorf("failed to inject KMS plugin sidecar: %w", err)
	}

	klog.Infof("Successfully injected KMS plugin sidecar container")
	return nil
}
