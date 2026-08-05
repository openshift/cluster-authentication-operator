package library

import (
	"os"

	"github.com/openshift/cluster-authentication-operator/test/library/image"
)

var (
	keycloakImage string
	squidImage    string
)

func init() {
	const (
		keycloakPullSpec = "quay.io/keycloak/keycloak:25.0"
		squidPullSpec    = "registry.redhat.io/rhel10/squid:10.2-1784702318"
	)

	mappedImages := image.GetMappedImages(map[string]int{
		keycloakPullSpec: -1,
		squidPullSpec:    -1,
	}, os.Getenv("KUBE_TEST_REPO"))

	keycloakImage = mappedImages[keycloakPullSpec]
	squidImage = mappedImages[squidPullSpec]
}
