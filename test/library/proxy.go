package library

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/utils/ptr"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
)

const (
	squidImage       = "docker.io/ubuntu/squid:7.2-26.04_edge"
	squidHTTPPort    = int32(3128)
	squidHTTPSPort   = int32(3129)
	squidServiceName = "squid-proxy"

	componentProxyCAConfigMapName = "v4-0-config-system-auth-proxy-ca"
)

// SaveAndRestoreProxyConfig snapshots the current spec.proxy on the operator
// Authentication CR and returns a cleanup function that restores it and waits
// for the operator to reconcile.
func SaveAndRestoreProxyConfig(t testing.TB, operatorClient *operatorclient.Clientset, configClient *configclient.Clientset) (operatorAuth *operatorv1.Authentication, cleanup func()) {
	ctx := context.TODO()

	auth, err := operatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get operator authentication CR: %v", err)
	}
	originalProxy := auth.Spec.Proxy.DeepCopy()

	return auth, func() {
		t.Log("cleaning up: restoring original proxy config")
		err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			fresh, err := operatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: failed to get operator auth: %v", err)
				return false, nil
			}
			if originalProxy != nil {
				fresh.Spec.Proxy = *originalProxy
			} else {
				fresh.Spec.Proxy = operatorv1.AuthenticationProxyConfig{}
			}
			if _, err := operatorClient.OperatorV1().Authentications().Update(ctx, fresh, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: failed to update operator auth (will retry): %v", err)
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			t.Logf("cleanup: failed to restore proxy config: %v", err)
			return
		}
		t.Log("cleanup: waiting for operator to pick up changes and stabilize")
		if err := WaitForOperatorToPickUpChanges(t, configClient.ConfigV1(), "authentication"); err != nil {
			t.Logf("cleanup: operator did not recover: %v", err)
		}
	}
}

// DeploySquidProxy deploys a Squid forward proxy that listens on both plain
// HTTP (port 3128) and HTTPS (port 3129). It generates a self-signed CA and
// serving certificate internally. Returns the HTTP and HTTPS proxy URLs,
// the PEM-encoded CA certificate (for trustedCA ConfigMaps when using https),
// the namespace name, and a cleanup function.
func DeploySquidProxy(t testing.TB, kubeClient kubernetes.Interface) (httpProxyURL, httpsProxyURL string, caCertPEM []byte, namespace string, cleanup func()) {
	ctx := context.TODO()

	namespace = NewTestNamespaceBuilder("e2e-proxy-").
		WithBaselinePSaEnforcement().
		WithLabels(CAOE2ETestLabels()).
		Create(t, kubeClient.CoreV1().Namespaces())

	cleanup = sync.OnceFunc(func() {
		if err := kubeClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil {
			t.Logf("error cleaning up proxy namespace %q: %v", namespace, err)
		}
	})

	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()

	ca := NewCertificateAuthorityCertificate(t, nil)
	serviceDNS := fmt.Sprintf("%s.%s.svc.cluster.local", squidServiceName, namespace)
	serverCert := NewServerCertificate(t, ca, serviceDNS)

	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate.Raw})
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate.Raw})

	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	if err != nil {
		t.Fatalf("failed to marshal server private key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})

	squidConfig := fmt.Sprintf(`http_port %d
https_port %d tls-cert=/etc/squid/tls/tls.crt tls-key=/etc/squid/tls/tls.key
pid_filename /tmp/squid.pid
acl all src all
http_access allow all
access_log /tmp/squid/access.log
cache_log /tmp/squid/cache.log
cache deny all
buffered_logs off
`, squidHTTPPort, squidHTTPSPort)

	_, err = kubeClient.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "squid-config"},
		Data:       map[string]string{"squid.conf": squidConfig},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create squid config: %v", err)
	}

	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "squid-tls"},
		Data: map[string][]byte{
			"tls.crt": serverCertPEM,
			"tls.key": serverKeyPEM,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create squid TLS secret: %v", err)
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   squidServiceName,
			Labels: map[string]string{"app": squidServiceName},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": squidServiceName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": squidServiceName},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "squid",
							Image: squidImage,
							Ports: []corev1.ContainerPort{
								{ContainerPort: squidHTTPPort, Protocol: corev1.ProtocolTCP},
								{ContainerPort: squidHTTPSPort, Protocol: corev1.ProtocolTCP},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "squid-config",
									MountPath: "/etc/squid/squid.conf",
									SubPath:   "squid.conf",
								},
								{
									Name:      "squid-tls",
									MountPath: "/etc/squid/tls",
									ReadOnly:  true,
								},
								{
									Name:      "squid-logs",
									MountPath: "/tmp/squid",
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt32(squidHTTPPort),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
							},
						},
						{
							Name:    "log",
							Image:   squidImage,
							Command: []string{"tail", "-F", "/tmp/squid/access.log"},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "squid-logs",
									MountPath: "/tmp/squid",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "squid-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "squid-config",
									},
								},
							},
						},
						{
							Name: "squid-tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "squid-tls",
								},
							},
						},
						{
							Name: "squid-logs",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}

	_, err = kubeClient.AppsV1().Deployments(namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create squid deployment: %v", err)
	}

	_, err = kubeClient.CoreV1().Services(namespace).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   squidServiceName,
			Labels: map[string]string{"app": squidServiceName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": squidServiceName},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       squidHTTPPort,
					TargetPort: intstr.FromInt32(squidHTTPPort),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       squidHTTPSPort,
					TargetPort: intstr.FromInt32(squidHTTPSPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create squid service: %v", err)
	}

	t.Logf("waiting for squid proxy deployment in %s to be ready", namespace)
	timeLimitedCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, err = watchtools.UntilWithSync(timeLimitedCtx,
		cache.NewListWatchFromClient(
			kubeClient.AppsV1().RESTClient(), "deployments", namespace,
			fields.OneTermEqualSelector("metadata.name", squidServiceName)),
		&appsv1.Deployment{},
		nil,
		func(event watch.Event) (bool, error) {
			d := event.Object.(*appsv1.Deployment)
			return d.Status.ReadyReplicas > 0, nil
		},
	)
	if err != nil {
		t.Fatalf("squid proxy deployment did not become ready: %v", err)
	}

	success = true

	serviceHost := fmt.Sprintf("%s.%s.svc.cluster.local", squidServiceName, namespace)
	httpProxyURL = fmt.Sprintf("http://%s:%d", serviceHost, squidHTTPPort)
	httpsProxyURL = fmt.Sprintf("https://%s:%d", serviceHost, squidHTTPSPort)
	success = true
	t.Logf("squid proxy deployed: http=%s https=%s", httpProxyURL, httpsProxyURL)
	return httpProxyURL, httpsProxyURL, caCertPEM, namespace, cleanup
}

// DeployProxyNetworkPolicies creates a NetworkPolicy on the Keycloak namespace
// that restricts ingress to only the proxy namespace. This ensures auth
// components can only reach Keycloak through the proxy.
//
// Note: egress policies on auth namespaces are not created because the
// operator-managed NetworkPolicies already have allow-all egress rules that
// cannot be overridden additively.
func DeployProxyNetworkPolicies(t testing.TB, kubeClient kubernetes.Interface, proxyNamespace, keycloakNamespace string) func() {
	ctx := context.TODO()

	keycloakPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-e2e-allow-only-from-proxy",
			Namespace: keycloakNamespace,
			Labels:    CAOE2ETestLabels(),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": proxyNamespace,
								},
							},
						},
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"policy-group.network.openshift.io/ingress": "",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := kubeClient.NetworkingV1().NetworkPolicies(keycloakNamespace).Create(ctx, keycloakPolicy, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create NetworkPolicy in %s: %v", keycloakNamespace, err)
	}
	t.Logf("created NetworkPolicy proxy-e2e-allow-only-from-proxy in %s", keycloakNamespace)

	return func() {
		if err := kubeClient.NetworkingV1().NetworkPolicies(keycloakNamespace).Delete(ctx, "proxy-e2e-allow-only-from-proxy", metav1.DeleteOptions{}); err != nil {
			t.Logf("error cleaning up NetworkPolicy in %s: %v", keycloakNamespace, err)
		}
	}
}

// GetSquidProxyLogs reads the Squid access log from the proxy pod via
// the log sidecar container that tails the access log file.
func GetSquidProxyLogs(kubeClient kubernetes.Interface, namespace string) (string, error) {
	ctx := context.TODO()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", squidServiceName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list squid pods in %s: %w", namespace, err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no squid proxy pods found in namespace %s", namespace)
	}

	container := "log"
	logBytes, err := kubeClient.CoreV1().Pods(namespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{
		Container: container,
	}).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get logs from container %s: %w", container, err)
	}

	return string(logBytes), nil
}

// WaitForSquidProxyTraffic polls the Squid proxy logs until it sees CONNECT or
// TCP_ entries, indicating traffic went through the proxy.
func WaitForSquidProxyTraffic(t testing.TB, kubeClient kubernetes.Interface, namespace string, timeout time.Duration) error {
	t.Logf("waiting up to %s for traffic in squid proxy logs", timeout)
	return wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		logs, err := GetSquidProxyLogs(kubeClient, namespace)
		if err != nil {
			t.Logf("failed to read squid logs: %v", err)
			return false, nil
		}
		if strings.Contains(logs, "CONNECT") || strings.Contains(logs, "TCP_") {
			t.Logf("detected proxy traffic in squid logs")
			return true, nil
		}
		return false, nil
	})
}

// VerifyOAuthServerDeploymentProxyConfig asserts that the OAuth server
// deployment has the expected proxy env var values and trustedCA volume/mount.
// Proxy env vars are always set; pass empty string to assert an unset proxy.
// When expectTrustedCAVolume is true, the v4-0-config-system-auth-proxy-ca
// volume and mount must exist; when false, they must be absent.
func VerifyOAuthServerDeploymentProxyConfig(t testing.TB, kubeClient kubernetes.Interface, expectedHTTPProxy, expectedHTTPSProxy, expectedNoProxy string, expectTrustedCAVolume bool) {
	ctx := context.TODO()

	var deployment *appsv1.Deployment
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		var err error
		deployment, err = kubeClient.AppsV1().Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to get oauth-openshift deployment: %v", err)
			return false, nil
		}

		envVars := make(map[string]string)
		for _, container := range deployment.Spec.Template.Spec.Containers {
			for _, env := range container.Env {
				switch env.Name {
				case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
					envVars[env.Name] = env.Value
				}
			}
		}

		if envVars["HTTP_PROXY"] != expectedHTTPProxy || envVars["HTTPS_PROXY"] != expectedHTTPSProxy {
			return false, nil
		}
		// Use superset check: the operator may add extra entries to NO_PROXY beyond
		// what the caller specifies (e.g. the kubernetes service IP for KUBERNETES_SERVICE_HOST).
		actualNoProxy := sets.New[string](strings.Split(envVars["NO_PROXY"], ",")...)
		expectedNoProxyEntries := sets.New[string](strings.Split(expectedNoProxy, ",")...)
		if !actualNoProxy.IsSuperset(expectedNoProxyEntries) {
			return false, nil
		}

		if matchTrustedCAVolume(deployment, expectTrustedCAVolume) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("OAuth server deployment proxy config did not match expected values within timeout")
	}
}

func matchTrustedCAVolume(deployment *appsv1.Deployment, expectPresent bool) bool {
	foundVolume := false
	for _, vol := range deployment.Spec.Template.Spec.Volumes {
		if vol.ConfigMap != nil && vol.ConfigMap.Name == componentProxyCAConfigMapName {
			foundVolume = true
			break
		}
	}

	foundMount := false
	for _, container := range deployment.Spec.Template.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			if mount.Name == componentProxyCAConfigMapName {
				foundMount = true
				break
			}
		}
	}

	if expectPresent {
		return foundVolume && foundMount
	}
	return !foundVolume && !foundMount
}

// VerifyTrustedCAConfigMapSynced checks that the trustedCA ConfigMap has been
// synced to the openshift-authentication namespace under the operator's
// hardcoded name (v4-0-config-system-auth-proxy-ca).
func VerifyTrustedCAConfigMapSynced(t testing.TB, kubeClient kubernetes.Interface, configMapName string) {
	ctx := context.TODO()

	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		cm, err := kubeClient.CoreV1().ConfigMaps("openshift-authentication").Get(ctx, componentProxyCAConfigMapName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return len(cm.Data) > 0, nil
	})
	if err != nil {
		t.Fatalf("trustedCA ConfigMap %s was not synced to openshift-authentication as %s within timeout", configMapName, componentProxyCAConfigMapName)
	}
}

// CheckFeatureGateEnabledOrSkip skips the test if the given feature gate is not enabled.
func CheckFeatureGateEnabledOrSkip(t testing.TB, configClient *configclient.Clientset, featureGateName configv1.FeatureGateName) {
	ctx := context.TODO()

	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get feature gates: %v", err)
	}

	if len(featureGates.Status.FeatureGates) != 1 {
		t.Fatalf("multiple feature gate versions detected — cluster may be upgrading")
	}

	for _, gate := range featureGates.Status.FeatureGates[0].Enabled {
		if gate.Name == featureGateName {
			t.Logf("feature gate %s is enabled", featureGateName)
			return
		}
	}

	t.Skipf("skipping: feature gate %s is not enabled", featureGateName)
}
