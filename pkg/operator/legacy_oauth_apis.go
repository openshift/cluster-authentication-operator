package operator

import (
	"fmt"
	"net"
	"strconv"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	apiregistrationv1informers "k8s.io/kube-aggregator/pkg/client/informers/externalversions/apiregistration/v1"

	"sigs.k8s.io/yaml"
)

const (
	kasNamespace      = "openshift-kube-apiserver"
	webhookSecretName = "webhook-authenticator"
)

type kasRevisionConfig struct {
	APIServerArguments map[string][]string `json:"apiServerArguments"`
}

type oidcAvailabilityChecker interface {
	AuthConfig() (*configv1.Authentication, error)
	OIDCAvailable() (bool, error)
}

type legacyOAuthAPIsObserver struct {
	authConfigChecker   oidcAvailabilityChecker
	featureGateAccessor featuregates.FeatureGateAccess
	services            corev1informers.ServiceInformer
	kasSecrets          corev1informers.SecretInformer
	kasConfigMaps       corev1informers.ConfigMapInformer
	apiServices         apiregistrationv1informers.APIServiceInformer
	kas                 operatorv1informers.KubeAPIServerInformer
}

func newLegacyOAuthAPIsObserver(
	authConfigChecker oidcAvailabilityChecker,
	featureGateAccessor featuregates.FeatureGateAccess,
	services corev1informers.ServiceInformer,
	kas operatorv1informers.KubeAPIServerInformer,
	kasSecrets corev1informers.SecretInformer,
	kasConfigMaps corev1informers.ConfigMapInformer,
	apiServices apiregistrationv1informers.APIServiceInformer,
) *legacyOAuthAPIsObserver {
	return &legacyOAuthAPIsObserver{
		authConfigChecker:   authConfigChecker,
		featureGateAccessor: featureGateAccessor,
		services:            services,
		kas:                 kas,
		kasSecrets:          kasSecrets,
		kasConfigMaps:       kasConfigMaps,
		apiServices:         apiServices,
	}
}

func (o *legacyOAuthAPIsObserver) shouldRemove() (bool, error) {
	webhookArchitectureRequired, err := externalOIDCWebhookArchitectureRequired(o.featureGateAccessor)
	if err != nil {
		return false, err
	}
	if webhookArchitectureRequired {
		return o.shouldRemoveForWebhookArchitecture()
	}
	return o.authConfigChecker.OIDCAvailable()
}

func (o *legacyOAuthAPIsObserver) shouldRemoveForWebhookArchitecture() (bool, error) {
	authConfig, err := o.authConfigChecker.AuthConfig()
	if err != nil {
		return false, err
	}
	if authConfig.Spec.Type != configv1.AuthenticationTypeOIDC {
		return false, nil
	}

	if ready, err := o.kasReadyForLegacyRemoval(); err != nil {
		return false, err
	} else if !ready {
		return false, nil
	}

	// Once KAS no longer needs the legacy endpoint, wait rather than recreate
	// legacy resources while the replacement is being prepared for direct OIDC.
	oidcAvailable, err := o.authConfigChecker.OIDCAvailable()
	if err != nil {
		return false, err
	}
	if !oidcAvailable {
		return false, fmt.Errorf("waiting for OIDC configuration to be available")
	}

	return true, nil
}

func (o *legacyOAuthAPIsObserver) removed() (bool, error) {
	if !o.services.Informer().HasSynced() {
		return false, fmt.Errorf("Service cache has not synchronized")
	}
	if !o.apiServices.Informer().HasSynced() {
		return false, fmt.Errorf("APIService cache has not synchronized")
	}
	return common.LegacyOAuthAPIsRemoved(o.services.Lister(), o.apiServices.Lister())
}

// kasReadyForLegacyRemoval checks that all current and pending target KAS revisions
// use direct OIDC or the dedicated token-review endpoint.
func (o *legacyOAuthAPIsObserver) kasReadyForLegacyRemoval() (bool, error) {
	if !o.services.Informer().HasSynced() {
		return false, fmt.Errorf("Service cache has not synchronized")
	}
	if !o.kas.Informer().HasSynced() {
		return false, fmt.Errorf("KAS cache has not synchronized")
	}
	if !o.kasConfigMaps.Informer().HasSynced() {
		return false, fmt.Errorf("KAS ConfigMap cache has not synchronized")
	}
	if !o.kasSecrets.Informer().HasSynced() {
		return false, fmt.Errorf("KAS Secret cache has not synchronized")
	}

	kas, err := o.kas.Lister().Get("cluster")
	if err != nil {
		return false, fmt.Errorf("getting KAS: %w", err)
	}

	if len(kas.Status.NodeStatuses) == 0 {
		return false, fmt.Errorf("no node statuses observed yet")
	}

	revisions := sets.New[int32]()
	for _, nodeStatus := range kas.Status.NodeStatuses {
		if nodeStatus.CurrentRevision <= 0 {
			return false, fmt.Errorf("unexpected revision number in status of KAS node %q: %d", nodeStatus.NodeName, nodeStatus.CurrentRevision)
		}
		if nodeStatus.TargetRevision < 0 {
			return false, fmt.Errorf("unexpected target revision number in status of KAS node %q: %d", nodeStatus.NodeName, nodeStatus.TargetRevision)
		}

		revisions.Insert(nodeStatus.CurrentRevision)
		if nodeStatus.TargetRevision != 0 {
			revisions.Insert(nodeStatus.TargetRevision)
		}
	}

	for _, revision := range sets.List(revisions) {
		revisionCfg, err := o.kasRevisionConfig(revision)
		if err != nil {
			return false, err
		}

		if kasRevisionUsesDirectOIDC(revisionCfg) {
			continue
		}

		tokenReview, err := o.kasRevisionUsesTokenReviewService(revision, revisionCfg)
		if err != nil || !tokenReview {
			return false, err
		}
	}

	return true, nil
}

// kasRevisionConfig loads and parses the KAS configuration for a revision.
func (o *legacyOAuthAPIsObserver) kasRevisionConfig(revision int32) (*kasRevisionConfig, error) {
	cmName := fmt.Sprintf("config-%d", revision)
	kasConfig, err := o.kasConfigMaps.Lister().ConfigMaps(kasNamespace).Get(cmName)
	if err != nil {
		return nil, fmt.Errorf("retrieving KAS config at revision %d: %w", revision, err)
	}

	configData := kasConfig.Data["config.yaml"]
	if len(configData) == 0 {
		return nil, fmt.Errorf("config.yaml in ConfigMap %s/%s is empty", kasNamespace, cmName)
	}

	config := &kasRevisionConfig{}
	if err := yaml.Unmarshal([]byte(configData), config); err != nil {
		return nil, fmt.Errorf("parsing ConfigMap %s/%s: %w", kasNamespace, cmName, err)
	}
	return config, nil
}

// kasRevisionUsesDirectOIDC checks that the configuration disables the token webhook
// and enables structured authentication through the expected config path.
func kasRevisionUsesDirectOIDC(config *kasRevisionConfig) bool {
	if len(config.APIServerArguments["authentication-token-webhook-config-file"]) > 0 {
		return false
	}
	paths := config.APIServerArguments["authentication-config"]
	return len(paths) == 1 && paths[0] == "/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"
}

// kasRevisionUsesTokenReviewService checks that a revision enables the token webhook and
// its revisioned kubeconfig targets the token-review Service URL and TLS identity.
func (o *legacyOAuthAPIsObserver) kasRevisionUsesTokenReviewService(revision int32, config *kasRevisionConfig) (bool, error) {
	paths := config.APIServerArguments["authentication-token-webhook-config-file"]
	if len(paths) != 1 || paths[0] != "/etc/kubernetes/static-pod-resources/secrets/webhook-authenticator/kubeConfig" {
		return false, nil
	}

	secretName := fmt.Sprintf("%s-%d", webhookSecretName, revision)
	webhookSecret, err := o.kasSecrets.Lister().Secrets(kasNamespace).Get(secretName)
	if err != nil {
		return false, fmt.Errorf("getting secret %s/%s: %w", kasNamespace, secretName, err)
	}

	kubeConfig, err := clientcmd.Load(webhookSecret.Data["kubeConfig"])
	if err != nil {
		return false, fmt.Errorf("loading kubeconfig from secret %s/%s: %w", kasNamespace, secretName, err)
	}

	currentContext := kubeConfig.Contexts[kubeConfig.CurrentContext]
	if currentContext == nil {
		return false, fmt.Errorf("webhook kubeconfig current context does not exist")
	}

	cluster := kubeConfig.Clusters[currentContext.Cluster]
	if cluster == nil {
		return false, fmt.Errorf("webhook kubeconfig current context cluster does not exist")
	}

	svc, err := o.services.Lister().Services("openshift-oauth-apiserver").Get("token-review")
	if errors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("getting service openshift-oauth-apiserver/token-review: %w", err)
	}
	if svc.Spec.ClusterIP == "" || len(svc.Spec.Ports) == 0 {
		return false, fmt.Errorf("cannot determine token-review Service address: missing ClusterIP or port")
	}

	expectedServer := "https://" + net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port))) + "/apis/oauth.openshift.io/v1/tokenreviews"
	return cluster.Server == expectedServer && cluster.TLSServerName == "token-review.openshift-oauth-apiserver.svc", nil
}
