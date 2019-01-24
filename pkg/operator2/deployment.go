package operator2

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	authv1alpha1 "github.com/openshift/cluster-authentication-operator/pkg/apis/authentication/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/v1alpha1helpers"
)

const hashAnnotation = authv1alpha1.GroupName + "/rvs-hash"

func (c *authOperator) getGeneration() int64 {
	deployment, err := c.deployments.Deployments(targetName).Get(targetName, metav1.GetOptions{})
	if err != nil {
		return -1
	}
	return deployment.Generation
}

func defaultDeployment(operatorConfig *authv1alpha1.AuthenticationOperatorConfig, syncData []idpSyncData, resourceVersions ...string) *appsv1.Deployment {
	replicas := int32(3) // TODO configurable?
	gracePeriod := int64(30)

	// TODO fix these names
	sessionVolumeName := targetName + "-secret"
	configVolumeName := targetName + "-configmap"

	volumes := []corev1.Volume{
		{
			Name: sessionVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: targetName,
				},
			},
		},
		{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: targetName,
					},
				},
			},
		},
		{
			Name: servingCertName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: servingCertName,
				},
			},
		},
	}

	mounts := []corev1.VolumeMount{
		{
			Name:      sessionVolumeName,
			ReadOnly:  true,
			MountPath: sessionMount,
		},
		{
			Name:      configVolumeName,
			ReadOnly:  true,
			MountPath: systemConfigPath,
		},
		{
			Name:      servingCertName,
			ReadOnly:  true,
			MountPath: servingCertMount,
		},
	}

	for _, d := range syncData {
		volumes, mounts = toVolumesAndMounts(d.configMaps, volumes, mounts)
		volumes, mounts = toVolumesAndMounts(d.secrets, volumes, mounts)
	}

	// force redeploy when any associated resource changes
	// we use a hash to prevent this value from growing indefinitely
	rvs := strings.Join(resourceVersions, ",")
	rvsHash := sha512.Sum512([]byte(rvs))
	rvsHashStr := base64.RawURLEncoding.EncodeToString(rvsHash[:])

	// make sure ApplyDeployment knows to update
	meta := defaultMeta()
	meta.Annotations[hashAnnotation] = rvsHashStr

	deployment := &appsv1.Deployment{
		ObjectMeta: meta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: defaultLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   targetName,
					Labels: defaultLabels(),
					Annotations: map[string]string{
						hashAnnotation: rvsHashStr,
					},
				},
				Spec: corev1.PodSpec{
					// we want to deploy on master nodes
					//NodeSelector: map[string]string{
					//	// empty string is correct
					//	"node-role.kubernetes.io/master": "",
					//},
					//Affinity: &corev1.Affinity{
					//	// spread out across master nodes rather than congregate on one
					//	PodAntiAffinity: &corev1.PodAntiAffinity{
					//		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
					//			Weight: 100,
					//			PodAffinityTerm: corev1.PodAffinityTerm{
					//				LabelSelector: &metav1.LabelSelector{
					//					MatchLabels: defaultLabels(),
					//				},
					//				TopologyKey: "kubernetes.io/hostname",
					//			},
					//		}},
					//	},
					//},
					//// toleration is a taint override. we can and should be scheduled on a master node.
					//Tolerations: []corev1.Toleration{
					//	{
					//		Key:      "node-role.kubernetes.io/master",
					//		Operator: corev1.TolerationOpExists,
					//		Effect:   corev1.TaintEffectNoSchedule,
					//	},
					//},
					ServiceAccountName:            targetName,
					RestartPolicy:                 corev1.RestartPolicyAlways,
					SchedulerName:                 corev1.DefaultSchedulerName,
					TerminationGracePeriodSeconds: &gracePeriod,
					SecurityContext:               &corev1.PodSecurityContext{},
					Containers: []corev1.Container{
						{
							Image:           v1alpha1helpers.GetImageEnv(),
							ImagePullPolicy: corev1.PullPolicy("IfNotPresent"),
							Name:            targetName,
							Command: []string{
								"hypershift",
								"openshift-osinserver",
								fmt.Sprintf("--config=%s/%s", systemConfigPath, configKey),
								fmt.Sprintf("--v=%d", getLogLevel(operatorConfig.Spec.LogLevel)),
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: containerPort,
								},
							},
							VolumeMounts:             mounts,
							ReadinessProbe:           defaultProbe(),
							LivenessProbe:            livenessProbe(),
							TerminationMessagePath:   "/dev/termination-log",
							TerminationMessagePolicy: corev1.TerminationMessagePolicy("File"),
							//Resources: corev1.ResourceRequirements{
							//	Requests: map[corev1.ResourceName]resource.Quantity{
							//		corev1.ResourceCPU:    resource.MustParse("2G"),
							//		corev1.ResourceMemory: resource.MustParse("2G"),
							//	},
							//},
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
				Port:   intstr.FromInt(containerPort),
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
	case operatorv1.Normal:
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
