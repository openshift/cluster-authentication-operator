package library

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
)

const servingSecretName = "serving-secret"

func boolptr(b bool) *bool {
	return &b
}

func deployPod(
	t *testing.T,
	clients *kubernetes.Clientset,
	routeClient routev1client.RouteV1Interface,
	name, image string,
	env []corev1.EnvVar,
	httpPort, httpsPort int32,
	volumes []corev1.Volume,
	volumeMounts []corev1.VolumeMount,
	resources corev1.ResourceRequirements,
	readinessProbe *corev1.Probe,
	livenessProbe *corev1.Probe,
	useTLS bool,
	command ...string,
) (namespace, host string, cleanup func()) {
	testContext := context.TODO()

	var err error
	cleanup = func() {}

	namespace = NewTestNamespaceBuilder("e2e-test-authentication-operator-").
		WithPrivilegedPSaEnforcement().
		WithLabels(CAOE2ETestLabels()).
		Create(t, clients.CoreV1().Namespaces())

	cleanup = func() {
		// remove the NS, it will take away all the resources create here along with it
		if err := clients.CoreV1().Namespaces().Delete(testContext, namespace, metav1.DeleteOptions{}); err != nil {
			t.Logf("error cleaning up a resource: %v", err)
		}
	}

	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	_, err = clients.CoreV1().ServiceAccounts(namespace).Create(
		testContext,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		},
		metav1.CreateOptions{},
	)

	saName := name
	pod := podTemplate(name, image, httpPort, httpsPort, command...)
	pod.Spec.Volumes = volumes
	pod.Spec.Containers[0].VolumeMounts = volumeMounts
	pod.Spec.Containers[0].Env = env
	pod.Spec.Containers[0].Resources = resources
	if readinessProbe != nil {
		pod.Spec.Containers[0].ReadinessProbe = readinessProbe
	}
	if livenessProbe != nil {
		pod.Spec.Containers[0].LivenessProbe = livenessProbe
	}
	pod.Spec.ServiceAccountName = saName

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": "e2e-tested-app"},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "e2e-tested-app"}},
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: pod.ObjectMeta,
				Spec:       pod.Spec,
			},
		},
	}

	roleBinding := &v1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "privileged-scc-to-default-sa",
		},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:openshift:scc:privileged",
		},
		Subjects: []v1.Subject{
			{
				Kind: "ServiceAccount",
				Name: saName,
			},
		},
	}

	_, err = clients.RbacV1().RoleBindings(namespace).Create(testContext, roleBinding, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clients.AppsV1().Deployments(namespace).Create(testContext, deployment, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = clients.CoreV1().Services(namespace).Create(testContext, svcTemplate(httpPort, httpsPort), metav1.CreateOptions{})
	require.NoError(t, err)

	timeLimitedCtx, cancel := context.WithTimeout(testContext, 10*time.Minute)
	defer cancel()
	_, err = watchtools.UntilWithSync(timeLimitedCtx,
		cache.NewListWatchFromClient(
			clients.AppsV1().RESTClient(), "deployments", namespace, fields.OneTermEqualSelector("metadata.name", deployment.Name)),
		&appsv1.Deployment{},
		nil,
		func(event watch.Event) (bool, error) {
			ds := event.Object.(*appsv1.Deployment)
			return ds.Status.ReadyReplicas > 0, nil
		},
	)
	require.NoError(t, err)

	route, err := routeClient.Routes(namespace).Create(testContext, routeTemplate(useTLS), metav1.CreateOptions{})
	require.NoError(t, err)

	host, err = WaitForRouteAdmitted(t, routeClient, route.Name, route.Namespace)
	require.NoError(t, err)

	return
}

func podTemplate(name, image string, httpPort, httpsPort int32, command ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": "e2e-tested-app",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "payload",
					Image: image,
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolptr(true),
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: httpsPort,
						},
						{
							ContainerPort: httpPort,
						},
					},
					Command: command,
				},
			},
		},
	}
}

func svcTemplate(httpPort, httpsPort int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "pod-svc",
			Labels: CAOE2ETestLabels(),
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": servingSecretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "e2e-tested-app",
			},
			Ports: []corev1.ServicePort{
				{
					Name: "https",
					Port: httpsPort,
				},
				{
					Name: "http",
					Port: httpPort,
				},
			},
		},
	}
}

func routeTemplate(useTLS bool) *routev1.Route {
	r := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-route",
		},
		Spec: routev1.RouteSpec{
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationEdge,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: "pod-svc",
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("http"),
			},
		},
	}

	if useTLS {
		r.Spec.TLS.Termination = routev1.TLSTerminationReencrypt
		r.Spec.Port = &routev1.RoutePort{
			TargetPort: intstr.FromString("https"),
		}
	}

	return r
}

func CleanIDPConfigByName(t *testing.T, configClient configv1client.OAuthInterface, idpName string) {
	config, err := configClient.Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("cleanup: failed to retrieve oauth/cluster: %v", err)
	}

	idpIndex := 0
	for _, idp := range config.Spec.IdentityProviders {
		if idp.Name == idpName {
			break
		}
		idpIndex++
	}

	// did not find the idp of name
	if idpIndex == len(config.Spec.IdentityProviders) {
		return
	}

	// tear the i-th element of config.Spec.IdentityProviders out
	providers := config.Spec.IdentityProviders[:idpIndex]
	if len(config.Spec.IdentityProviders) > idpIndex+1 {
		// i is not the latest element, append the remainder
		providers = append(providers, config.Spec.IdentityProviders[idpIndex+1:]...)
	}

	config.Spec.IdentityProviders = providers
	if _, err := configClient.Update(context.TODO(), config, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("cleanup: failed to update oauth/cluster: %v", err)
	}
}

func IDPCleanupWrapper(cleanup func()) func() {
	return func() {
		// allow keeping the IdP for manual testing
		if len(os.Getenv("OPENSHIFT_KEEP_IDP")) > 0 {
			return
		}

		cleanup()
	}
}

// labels for listing/deleting stuff by hand, e.g. NS or simple openshift-config
// NS CMs and Secrets cleanup
func CAOE2ETestLabels() map[string]string {
	return map[string]string{
		"e2e-test": "openshift-authentication-operator",
	}
}

func addOIDCIDentityProvider(
	t *testing.T,
	kubeClients *kubernetes.Clientset,
	configClient *configv1client.ConfigV1Client,
	clientID, clientSecret, idpName, idpURL string,
	claims configv1.OpenIDClaims,
	directExternalOIDC bool) ([]func(), error) {
	var cleanups []func()

	secretName := idpName + "-secret"
	_, err := kubeClients.CoreV1().Secrets("openshift-config").Create(context.TODO(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:   secretName,
				Labels: CAOE2ETestLabels(),
			},
			Data: map[string][]byte{
				"clientSecret": []byte(clientSecret),
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return cleanups, fmt.Errorf("failed to create keycloak client secret: %v", err)
	}
	cleanups = append(cleanups, func() {
		if err := kubeClients.CoreV1().Secrets("openshift-config").Delete(context.TODO(), secretName, metav1.DeleteOptions{}); err != nil {
			t.Logf("cleanup failed for secret 'openshift-config/%s'", secretName)
		}
	})

	caCMName := idpName + "-ca"
	// configure the default ingress CA as the CA for the IdP in the openshift-config NS
	cleanups = append(cleanups, SyncDefaultIngressCAToConfig(t, kubeClients.CoreV1(), caCMName))

	if !directExternalOIDC {
		idpClean, err := addIdentityProvider(t, configClient,
			&configv1.IdentityProvider{
				Name:          idpName,
				MappingMethod: configv1.MappingMethodClaim,
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type: configv1.IdentityProviderTypeOpenID,
					OpenID: &configv1.OpenIDIdentityProvider{
						ClientID: clientID,
						ClientSecret: configv1.SecretNameReference{
							Name: secretName,
						},
						ExtraScopes: []string{"profile", "email"},
						Claims:      claims,
						Issuer:      idpURL,
						CA: configv1.ConfigMapNameReference{
							Name: caCMName,
						},
					},
				},
			})
		if err != nil {
			return cleanups, fmt.Errorf("failed to add identity provider to oauth server: %v", err)
		}

		cleanups = append(cleanups, idpClean...)
	}

	return cleanups, err
}

func addIdentityProvider(t *testing.T, configClient *configv1client.ConfigV1Client, idp *configv1.IdentityProvider) ([]func(), error) {
	cleanups := []func(){}

	oauth, err := configClient.OAuths().Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return cleanups, err
	}

	oauthCopy := oauth.DeepCopy()
	oauthCopy.Spec.IdentityProviders = append(oauth.Spec.IdentityProviders, *idp)

	_, err = configClient.OAuths().Update(context.TODO(), oauthCopy, metav1.UpdateOptions{})
	if err != nil {
		return cleanups, fmt.Errorf("failed to add an identity provider: %v", err)
	}

	cleanups = append(cleanups, func() {
		CleanIDPConfigByName(t, configClient.OAuths(), idp.Name)
	})

	if err := WaitForOperatorToPickUpChanges(t, configClient, "authentication"); err != nil {
		return cleanups, err
	}

	return cleanups, err
}
