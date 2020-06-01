package operator2

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
)

func defaultDeployment(
	operatorConfig *operatorv1.Authentication,
	syncData *configSyncData,
	routerSecret *corev1.Secret,
	proxyConfig *configv1.Proxy,
	operatorDeployment *appsv1.Deployment,
	resourceVersions ...string,
) *appsv1.Deployment {
	replicas := int32(2) // TODO configurable?
	tolerationSeconds := int64(120)
	readOnlyFileSystem := false

	var (
		volumes []corev1.Volume
		mounts  []corev1.VolumeMount
	)

	for _, data := range []volume{
		{
			name:      "v4-0-config-system-session",
			configmap: false,
			path:      "/var/config/system/secrets/v4-0-config-system-session",
			keys:      []string{"v4-0-config-system-session"},
		},
		{
			name:      "v4-0-config-system-cliconfig",
			configmap: true,
			path:      "/var/config/system/configmaps/v4-0-config-system-cliconfig",
			keys:      []string{"v4-0-config-system-cliconfig"},
		},
		{
			name:      "v4-0-config-system-serving-cert",
			configmap: false,
			path:      "/var/config/system/secrets/v4-0-config-system-serving-cert",
			keys:      []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey},
		},
		{
			name:      "v4-0-config-system-service-ca",
			configmap: true,
			path:      "/var/config/system/configmaps/v4-0-config-system-service-ca",
			keys:      []string{"service-ca.crt"},
		},
		{
			name:      "v4-0-config-system-router-certs",
			configmap: false,
			path:      "/var/config/system/secrets/v4-0-config-system-router-certs",
			keys:      sets.StringKeySet(routerSecret.Data).List(),
		},
		{
			name:      "v4-0-config-system-ocp-branding-template",
			configmap: false,
			path:      "/var/config/system/secrets/v4-0-config-system-ocp-branding-template",
			keys:      []string{configv1.LoginTemplateKey, configv1.ProviderSelectionTemplateKey, configv1.ErrorsTemplateKey},
		},
		{
			name:      "v4-0-config-system-trusted-ca-bundle",
			configmap: true,
			path:      "/var/config/system/configmaps/v4-0-config-system-trusted-ca-bundle",
			// make this config map volume optional as it may not always exist
			// this will prevent the node from blocking the container create process when the resource is missing
			optional: true,
		},
	} {
		v, m := data.split()
		volumes = append(volumes, v)
		mounts = append(mounts, m)
	}

	volumes, mounts = toVolumesAndMounts(syncData.idpConfigMaps, volumes, mounts)
	volumes, mounts = toVolumesAndMounts(syncData.idpSecrets, volumes, mounts)
	volumes, mounts = toVolumesAndMounts(syncData.tplSecrets, volumes, mounts)

	// force redeploy when any associated resource changes
	// we use a hash to prevent this value from growing indefinitely
	// need to sort first in order to get a stable array
	sort.Strings(resourceVersions)
	rvs := strings.Join(resourceVersions, ",")
	klog.V(4).Infof("tracked resource versions: %s", rvs)
	rvsHash := sha512.Sum512([]byte(rvs))
	rvsHashStr := base64.RawURLEncoding.EncodeToString(rvsHash[:])
	gracePeriod := int64(40)

	// make sure ApplyDeployment knows to update
	meta := defaultMeta()
	meta.Annotations[deploymentVersionHashKey] = rvsHashStr
	deployment := &appsv1.Deployment{
		ObjectMeta: meta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: defaultLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta,
				Spec: corev1.PodSpec{
					ServiceAccountName: "oauth-openshift",
					Containers: []corev1.Container{
						{
							Image:           oauthserverImage,
							ImagePullPolicy: getImagePullPolicy(operatorDeployment),
							Name:            "oauth-openshift",
							Command:         []string{"/bin/bash", "-ec"},
							Args: []string{fmt.Sprintf(`
if [ -s %s ]; then
    echo "Copying system trust bundle"
    cp -f %s /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
fi
exec oauth-server osinserver --config=%s --v=%d
`, `/var/config/system/configmaps/v4-0-config-system-trusted-ca-bundle/ca-bundle.crt`,
								`/var/config/system/configmaps/v4-0-config-system-trusted-ca-bundle/ca-bundle.crt`,
								`/var/config/system/configmaps/v4-0-config-system-cliconfig/v4-0-config-system-cliconfig`, getLogLevel(operatorConfig.Spec.LogLevel))},
							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 6443,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem: &readOnlyFileSystem, // false because of the `cp` in args
							},
							VolumeMounts:   mounts,
							Env:            proxyConfigToEnvVars(proxyConfig),
							ReadinessProbe: defaultProbe(),
							LivenessProbe:  livenessProbe(),
							Lifecycle: &corev1.Lifecycle{
								// Delay shutdown by 25s to ensure existing connections are drained
								// * 5s for endpoint propagation on delete
								// * 5s for route reload
								// * 15s for the longest running request to finish
								PreStop: &corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"sleep", "25"},
									},
								},
							},
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							Resources: corev1.ResourceRequirements{
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    resource.MustParse("10m"),
									corev1.ResourceMemory: resource.MustParse("50Mi"),
								},
							},
						},
					},
					TerminationGracePeriodSeconds: &gracePeriod,
					// deploy on master nodes
					NodeSelector: map[string]string{
						"node-role.kubernetes.io/master": "",
					},
					PriorityClassName: "system-cluster-critical",
					Affinity: &corev1.Affinity{
						// spread out across master nodes rather than congregate on one
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: defaultLabels(),
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							}},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "node-role.kubernetes.io/master",
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Key:               "node.kubernetes.io/unreachable",
							Operator:          corev1.TolerationOpExists,
							Effect:            corev1.TaintEffectNoExecute,
							TolerationSeconds: &tolerationSeconds,
						},
						{
							Key:               "node.kubernetes.io/not-ready",
							Operator:          corev1.TolerationOpExists,
							Effect:            corev1.TaintEffectNoExecute,
							TolerationSeconds: &tolerationSeconds,
						},
					},
					Volumes: volumes,
				},
			},
		},
	}
	return deployment
}

func defaultProbe() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/healthz",
				Port:   intstr.FromInt(6443),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		TimeoutSeconds:   1,
		PeriodSeconds:    10,
		SuccessThreshold: 1,
		FailureThreshold: 3,
	}
}

func livenessProbe() *corev1.Probe {
	probe := defaultProbe()
	probe.InitialDelaySeconds = 30
	return probe
}

func toVolumesAndMounts(data map[string]sourceData, volumes []corev1.Volume, mounts []corev1.VolumeMount) ([]corev1.Volume, []corev1.VolumeMount) {
	// iterate in a define order otherwise we will change the deployment's spec for no reason
	names := sets.StringKeySet(data).List()
	for _, name := range names {
		volumes = append(volumes, data[name].volume)
		mounts = append(mounts, data[name].mount)
	}
	return volumes, mounts
}

func getLogLevel(logLevel operatorv1.LogLevel) int {
	switch logLevel {
	case operatorv1.Normal, "": // treat empty string to mean the default
		return 2
	case operatorv1.Debug:
		return 4
	case operatorv1.Trace:
		return 6
	case operatorv1.TraceAll:
		return 100 // this is supposed to be 8 but I prefer "all" to really mean all
	default:
		return 0
	}
}

// tie the operand's image pull policy to the operator's image pull policy
// this makes it easy during development to change both the operator and
// operand's image once the CVO is configured to no longer manage the operator
func getImagePullPolicy(operatorDeployment *appsv1.Deployment) corev1.PullPolicy {
	containers := operatorDeployment.Spec.Template.Spec.Containers
	if len(containers) == 0 {
		return corev1.PullIfNotPresent
	}
	return containers[0].ImagePullPolicy
}

func proxyConfigToEnvVars(proxy *configv1.Proxy) []corev1.EnvVar {
	envVars := []corev1.EnvVar{}

	envVars = appendEnvVar(envVars, "NO_PROXY", proxy.Status.NoProxy)
	envVars = appendEnvVar(envVars, "HTTP_PROXY", proxy.Status.HTTPProxy)
	envVars = appendEnvVar(envVars, "HTTPS_PROXY", proxy.Status.HTTPSProxy)

	return envVars
}

func appendEnvVar(envVars []corev1.EnvVar, envName, envVal string) []corev1.EnvVar {
	if len(envVal) > 0 {
		return append(envVars, corev1.EnvVar{Name: envName, Value: envVal})
	}

	return envVars
}

type volume struct {
	name       string
	configmap  bool
	path       string
	keys       []string
	mappedKeys map[string]string
	optional   bool
}

func (v *volume) split() (corev1.Volume, corev1.VolumeMount) {
	vol := corev1.Volume{
		Name: v.name,
	}

	var items []corev1.KeyToPath
	// maps' keys are random,  we need to sort the output to prevent redeployment hotloops
	for _, key := range sets.StringKeySet(v.mappedKeys).List() {
		items = append(items, corev1.KeyToPath{
			Key:  key,
			Path: v.mappedKeys[key],
		})
	}

	for _, key := range v.keys {
		items = append(items, corev1.KeyToPath{
			Key:  key,
			Path: key,
		})
	}

	if v.configmap {
		vol.ConfigMap = &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: v.name,
			},
			Items:    items,
			Optional: &v.optional,
		}
	} else {
		vol.Secret = &corev1.SecretVolumeSource{
			SecretName: v.name,
			Items:      items,
			Optional:   &v.optional,
		}
	}

	return vol, corev1.VolumeMount{
		Name:      v.name,
		ReadOnly:  true,
		MountPath: v.path,
	}
}
