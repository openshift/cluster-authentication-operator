package libraryoutputresources

func ExactResource(group, resource, namespace, name string) ExactResourceID {
	return ExactResourceID{
		OutputResourceTypeIdentifier: OutputResourceTypeIdentifier{
			Group:    group,
			Resource: resource,
		},
		Namespace: namespace,
		Name:      name,
	}
}

func GeneratedResource(group, resource, namespace, name string) GeneratedResourceID {
	return GeneratedResourceID{
		OutputResourceTypeIdentifier: OutputResourceTypeIdentifier{
			Group:    group,
			Resource: resource,
		},
		Namespace:     namespace,
		GeneratedName: name,
	}
}

func ExactSecret(namespace, name string) ExactResourceID {
	return ExactResource("", "secrets", namespace, name)
}

func ExactConfigMap(namespace, name string) ExactResourceID {
	return ExactResource("", "configmaps", namespace, name)
}

func ExactNamespace(name string) ExactResourceID {
	return ExactResource("", "namespaces", "", name)
}

func ExactServiceAccount(namespace, name string) ExactResourceID {
	return ExactResource("", "serviceaccounts", namespace, name)
}

func ExactDeployment(namespace, name string) ExactResourceID {
	return ExactResource("apps", "deployments", namespace, name)
}

func ExactDaemonSet(namespace, name string) ExactResourceID {
	return ExactResource("apps", "daemonsets", namespace, name)
}

func ExactClusterOperator(name string) ExactResourceID {
	return ExactResource("config.openshift.io", "clusteroperators", "", name)
}

func ExactLowLevelOperator(resource string) ExactResourceID {
	return ExactResource("operator.openshift.io", resource, "", "cluster")
}

func ExactClusterRole(name string) ExactResourceID {
	return ExactResource("rbac.authorization.k8s.io", "clusterroles", "", name)
}

func ExactClusterRoleBinding(name string) ExactResourceID {
	return ExactResource("rbac.authorization.k8s.io", "clusterrolebindings", "", name)
}

func ExactRole(namespace, name string) ExactResourceID {
	return ExactResource("rbac.authorization.k8s.io", "roles", "", name)
}

func ExactRoleBinding(namespace, name string) ExactResourceID {
	return ExactResource("rbac.authorization.k8s.io", "rolebindings", "", name)
}

func ExactConfigResource(resource string) ExactResourceID {
	return ExactResource("config.openshift.io", resource, "", "cluster")
}

func GeneratedCSR(generateName string) GeneratedResourceID {
	return GeneratedResource("certificates.k8s.io", "certificatesigningrequests", "", generateName)
}
