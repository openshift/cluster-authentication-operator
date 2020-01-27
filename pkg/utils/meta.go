package utils

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DefaultMetaOAuthServerResources() v1.ObjectMeta {
	return v1.ObjectMeta{
		Name:            "oauth-openshift",
		Namespace:       "openshift-authentication",
		Labels:          DefaultLabelsOAuthServerResources(),
		Annotations:     map[string]string{},
		OwnerReferences: nil, // TODO
	}
}

func DefaultLabelsOAuthServerResources() map[string]string {
	return map[string]string{
		"app": "oauth-openshift",
	}
}
