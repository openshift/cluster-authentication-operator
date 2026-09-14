package deploymentutil

import corev1 "k8s.io/api/core/v1"

// ProxyEnvVars returns the non-empty proxy environment variables in the order
// used by authentication workloads.
func ProxyEnvVars(httpProxy, httpsProxy, noProxy string) []corev1.EnvVar {
	var envVars []corev1.EnvVar
	envVars = appendEnvVar(envVars, "NO_PROXY", noProxy)
	envVars = appendEnvVar(envVars, "HTTP_PROXY", httpProxy)
	envVars = appendEnvVar(envVars, "HTTPS_PROXY", httpsProxy)
	return envVars
}

func appendEnvVar(envVars []corev1.EnvVar, envName, envVal string) []corev1.EnvVar {
	if len(envVal) > 0 {
		return append(envVars, corev1.EnvVar{Name: envName, Value: envVal})
	}
	return envVars
}
