package library

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// NewClientConfigForTest returns a config configured to connect to the api server
func NewClientConfigForTest(t *testing.T) *rest.Config {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: api.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		fmt.Printf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	return config
}

// GenerateOAuthTokenPair returns two tokens to use with OpenShift OAuth-based authentication.
// The first token is a private token meant to be used as a Bearer token to send
// queries to the API, the second token is a hashed token meant to be stored in
// the database.
func GenerateOAuthTokenPair() (privToken, pubToken string) {
	const sha256Prefix = "sha256~"
	randomToken := fmt.Sprintf("nottoorandom%d", mathrand.Int())
	hashed := sha256.Sum256([]byte(randomToken))
	return sha256Prefix + string(randomToken), sha256Prefix + base64.RawURLEncoding.EncodeToString(hashed[:])
}
