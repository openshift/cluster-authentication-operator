package library

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
)

func AddKeycloakIDP(
	t *testing.T,
	kubeconfig *rest.Config,
) (idpURL, idpName string, cleanups []func()) {
	kubeClients, err := kubernetes.NewForConfig(kubeconfig)
	require.NoError(t, err)

	routeClient, err := routev1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	configClient, err := configv1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	nsName, keycloakHost, cleanup := deployPod(t, kubeClients, routeClient,
		"keycloak",
		"quay.io/keycloak/keycloak:latest",
		[]corev1.EnvVar{
			// configure password for GitLab root user
			{Name: "KEYCLOAK_USER", Value: "admin"},
			{Name: "KEYCLOAK_PASSWORD", Value: "password"},
		},
		8080,
		8443,
		[]corev1.Volume{
			{
				Name: "certkeypair",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: servingSecretName,
					},
				},
			},
		},
		[]corev1.VolumeMount{
			{
				Name:      "certkeypair",
				MountPath: "/etc/x509/https",
				ReadOnly:  true,
			},
		},
		corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("1000m"),
				"memory": resource.MustParse("700Mi"),
			},
		},
		true,
	)
	cleanups = []func(){cleanup}
	defer func() {
		if err != nil {
			for _, c := range cleanups {
				c()
			}
		}
	}()

	keycloakURL := "https://" + keycloakHost + "/auth/realms/master"

	transport, err := rest.TransportFor(kubeconfig)
	require.NoError(t, err)

	// TODO: add health and readiness instead?
	err = WaitForHTTPStatus(t, 10*time.Minute, &http.Client{Transport: transport}, keycloakURL, http.StatusOK)
	require.NoError(t, err)

	openshiftIDPName := fmt.Sprintf("keycloak-test-%s", nsName)

	// create a keycloak REST client and authenticate to the API
	kcClient := KeycloakClientFor(t, transport, keycloakURL, "master")
	err = kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
	require.NoError(t, err)

	clientList, err := kcClient.ListClients()
	require.NoError(t, err)

	var adminClientId, passwdClientId, passwdClientClientId string
	for _, c := range clientList {
		if clientID := c["clientId"].(string); clientID == "admin-cli" {
			adminClientId = c["id"].(string)
		} else if len(c["redirectUris"].([]interface{})) > 0 {
			// just reuse one other client that's already there
			passwdClientId = c["id"].(string)
			passwdClientClientId = clientID
		}

		if len(passwdClientId) > 0 && len(adminClientId) > 0 {
			break
		}
	}

	// change the client's access token timeout just in case we need it for the test
	err = kcClient.UpdateClientAccessTokenTimeout(adminClientId, 60*30)
	require.NoError(t, err)

	// reauthenticate for a new, longer-lived token
	err = kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
	require.NoError(t, err)

	clientSecret, err := kcClient.RegenerateClientSecret(passwdClientId)
	require.NoError(t, err)

	idpCleans, err := addOIDCIDentityProvider(t, kubeClients, configClient, passwdClientClientId, clientSecret, openshiftIDPName, keycloakURL)
	cleanups = append(cleanups, idpCleans...)
	require.NoError(t, err, "failed to configure the identity provider")

	return keycloakURL, openshiftIDPName, cleanups
}

type keycloakClient struct {
	keycloakAdminURL *url.URL
	realm            string
	testT            *testing.T
	token            string
	client           *http.Client
}

// KeycloakClientFor creates a Keycloak REST client for the default (master) realm
// using the supplied transport
func KeycloakClientFor(t *testing.T, transport http.RoundTripper, keycloakURL, keycloakRealm string) *keycloakClient {
	u, err := url.Parse(keycloakURL)
	require.NoError(t, err)

	u.Path = "/auth/admin/realms/" + keycloakRealm

	client := &http.Client{
		Transport: transport,
	}

	c := &keycloakClient{
		client:           client,
		keycloakAdminURL: u,
		realm:            keycloakRealm,
		testT:            t,
	}

	return c
}

func (kc *keycloakClient) AuthenticatePassword(clientID, clientSecret, name, password string) error {
	data := url.Values{
		"username":   []string{name},
		"password":   []string{password},
		"grant_type": []string{"password"},
		"client_id":  []string{clientID},
	}
	if len(clientSecret) > 0 {
		data.Add("client_secret", clientSecret)
	}

	authURL := *kc.keycloakAdminURL
	authURL.Path = "/auth/realms/" + kc.realm + "/protocol/openid-connect/token"
	authReq, err := http.NewRequest(http.MethodPost, authURL.String(), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kc.client.Do(authReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	authResp := map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &authResp); err != nil {
		return err
	}

	accessToken := authResp["access_token"].(string)
	if len(accessToken) == 0 {
		return fmt.Errorf("failed to retrieve an access token: %q - %q", authResp["error"], authResp["error_description"])
	}
	kc.token = accessToken

	return nil
}

// UpdateClientAccessTokenTimeout updates the timeout for a client of the given id
// timeout is a timeout in seconds
func (kc *keycloakClient) UpdateClientAccessTokenTimeout(id string, timeout int32) error {
	changes := map[string]interface{}{
		"attributes": map[string]interface{}{
			"access.token.lifespan": timeout,
		},
	}

	return kc.UpdateClient(id, changes)
}

// UpdateClientDirectAccessGrantsEnabled updates the `directAccessGrantsEnabled`
// attribute of the client which influences whether the password grant is allowed
// via the client or not
func (kc *keycloakClient) UpdateClientDirectAccessGrantsEnabled(id string, allow bool) error {
	changes := map[string]interface{}{
		"directAccessGrantsEnabled": allow,
	}

	return kc.UpdateClient(id, changes)
}

func (kc *keycloakClient) UpdateClient(id string, changedFields map[string]interface{}) error {
	client, err := kc.GetClient(id)
	if err != nil {
		return err
	}

	for k, v := range changedFields {
		client[k] = v
	}

	clientBytes, err := json.Marshal(client)
	if err != nil {
		return err
	}

	clientsURL := *kc.keycloakAdminURL
	clientsURL.Path += "/clients/" + id
	resp, err := kc.Do(http.MethodPut, clientsURL.String(), bytes.NewBuffer(clientBytes))

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed updating client %q: %s: %s", id, resp.Status, respBytes)
	}

	return nil
}

// GetClient retrieves a client based on its id (NOTE: id != clientID)
func (kc *keycloakClient) GetClient(id string) (map[string]interface{}, error) {
	clientsURL := *kc.keycloakAdminURL
	clientsURL.Path += "/clients/" + id

	resp, err := kc.Do(http.MethodGet, clientsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting the client %q failed: %s: %s", id, resp.Status, respBytes)
	}

	client := map[string]interface{}{}
	err = json.Unmarshal(respBytes, &client)

	return client, err
}

func (kc *keycloakClient) GetClientByClientID(clientID string) (map[string]interface{}, error) {
	clients, err := kc.ListClients()
	if err != nil {
		return nil, err
	}

	for _, c := range clients {
		if c["clientId"].(string) == clientID {
			return c, nil
		}
	}

	return nil, fmt.Errorf("client with clientID %q not found", clientID)
}

// GetClient retrieves a client based on its id (NOTE: id != name)
func (kc *keycloakClient) ListClients() ([]map[string]interface{}, error) {
	clientsURL := *kc.keycloakAdminURL
	clientsURL.Path += "/clients"

	resp, err := kc.Do(http.MethodGet, clientsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing clients failed: %s: %s", resp.Status, respBytes)
	}

	clients := []map[string]interface{}{}
	err = json.Unmarshal(respBytes, &clients)

	return clients, err
}

func (kc *keycloakClient) RegenerateClientSecret(id string) (string, error) {
	clientRegenURL := *kc.keycloakAdminURL
	clientRegenURL.Path += "/clients/" + id + "/client-secret"

	resp, err := kc.Do(http.MethodPost, clientRegenURL.String(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("regenerating %q client's secret failed: %s: %s", id, resp.Status, respBytes)
	}

	secret := map[string]string{}
	err = json.Unmarshal(respBytes, &secret)

	secretVal, ok := secret["value"]
	if !ok {
		return "", fmt.Errorf("failed to retrieve new secret for client %q", id)
	}

	return secretVal, nil
}

func (kc *keycloakClient) Do(method, url string, body io.Reader) (*http.Response, error) {
	if len(kc.token) == 0 {
		return nil, fmt.Errorf("authenticate first")
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", kc.token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return kc.client.Do(req)
}
