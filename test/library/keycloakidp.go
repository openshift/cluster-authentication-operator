package library

import (
	"bytes"
	"context"
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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
)

func AddKeycloakIDP(
	t *testing.T,
	kubeconfig *rest.Config,
	directOIDC bool,
) (idpURL, idpName string, cleanups []func()) {
	kubeClients, err := kubernetes.NewForConfig(kubeconfig)
	require.NoError(t, err)

	routeClient, err := routev1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	configClient, err := configv1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	readinessProbe := corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/health/ready",
				Port:   intstr.FromInt(9000),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 10,
	}
	livenessProbe := corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/health/live",
				Port:   intstr.FromInt(9000),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 10,
	}

	nsName, keycloakHost, cleanup := deployPod(t, kubeClients, routeClient,
		"keycloak",
		"quay.io/keycloak/keycloak:25.0",
		[]corev1.EnvVar{
			// configure password for Keycloak root user
			{Name: "KEYCLOAK_ADMIN", Value: "admin"},
			{Name: "KEYCLOAK_ADMIN_PASSWORD", Value: "password"},
			{Name: "KC_HEALTH_ENABLED", Value: "true"},
			{Name: "KC_HOSTNAME_STRICT", Value: "false"},
			{Name: "KC_PROXY", Value: "reencrypt"},
			{Name: "KC_HTTPS_CERTIFICATE_FILE", Value: "/etc/x509/https/tls.crt"},
			{Name: "KC_HTTPS_CERTIFICATE_KEY_FILE", Value: "/etc/x509/https/tls.key"},
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
				"cpu":    resource.MustParse("500m"),
				"memory": resource.MustParse("700Mi"),
			},
		},
		&readinessProbe,
		&livenessProbe,
		true,
		"/opt/keycloak/bin/kc.sh", "start",
	)
	cleanups = []func(){cleanup}
	defer func() {
		if err != nil {
			for _, c := range cleanups {
				c()
			}
		}
	}()

	keycloakBaseURL := "https://" + keycloakHost

	transport, err := rest.TransportFor(kubeconfig)
	require.NoError(t, err)

	openshiftIDPName := fmt.Sprintf("keycloak-test-%s", nsName)

	keycloakURL := keycloakBaseURL + "/realms/master"

	// create a keycloak REST client and authenticate to the API
	kcClient := KeycloakClientFor(t, transport, keycloakURL, "master")

	// even though configured via env vars and even though we checked Keycloak reports
	// ready on /health/ready, it still appears that we may need some time to log in properly
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
		if err != nil {
			t.Logf("failed to authenticate to Keycloak: %v", err)
			return false, nil
		}
		return true, nil
	})
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

	const groupsClaimName = "groups"
	require.NoError(t, kcClient.CreateClientGroupMapper(passwdClientId, "test-groups-mapper", groupsClaimName))

	idpCleans, err := addOIDCIDentityProvider(t,
		kubeClients,
		configClient,
		passwdClientClientId, clientSecret,
		openshiftIDPName,
		keycloakURL,
		configv1.OpenIDClaims{
			PreferredUsername: []string{"preferred_username"},
			Groups:            []configv1.OpenIDClaim{groupsClaimName},
		},
		directOIDC,
	)
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

	u.Path = "/admin/realms/" + keycloakRealm

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
	authURL.Path = "/realms/" + kc.realm + "/protocol/openid-connect/token"
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

	accessToken, ok := authResp["access_token"].(string)
	if !ok || len(accessToken) == 0 {
		errorMessage := "failed to retrieve an access token"
		if serverErrorMessage, ok := authResp["error"]; ok {
			errorMessage = fmt.Sprintf("%s. Server error was: %s", errorMessage, serverErrorMessage)
			if serverErrorDescription, ok := authResp["error_description"]; ok {
				errorMessage = fmt.Sprintf("%s - %s", errorMessage, serverErrorDescription)
			}
		}
		return fmt.Errorf(errorMessage)
	}

	kc.token = accessToken

	return nil
}

func (kc *keycloakClient) CreateClientGroupMapper(clientId, mapperName, groupsClaimName string) error {
	mappersURL := *kc.keycloakAdminURL
	mappersURL.Path += "/clients/" + clientId + "/protocol-mappers/models"

	mapper := map[string]interface{}{
		"name":           mapperName,
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-group-membership-mapper", // protocol-mapper type provided by Keycloak
		"config": map[string]string{
			"full.path":            "false",
			"id.token.claim":       "true",
			"access.token.claim":   "false",
			"userinfo.token.claim": "true",
			"claim.name":           groupsClaimName,
		},
	}

	mapperBytes, err := json.Marshal(mapper)
	if err != nil {
		return err
	}

	// Keycloak does not return the object on successful create so there's no need to attempt to retrieve it from the response
	resp, err := kc.Do(http.MethodPost, mappersURL.String(), bytes.NewBuffer(mapperBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed creating mapper %q: %s %s", mapperName, resp.Status, respBytes)
	}

	return nil
}

func (kc *keycloakClient) CreateGroup(groupName string) error {
	groupsURL := *kc.keycloakAdminURL
	groupsURL.Path += "/groups"

	group := map[string]interface{}{
		"name": groupName,
	}

	groupBytes, err := json.Marshal(group)
	if err != nil {
		return err
	}

	// Keycloak does not return the object on successful create so there's no need to attempt to retrieve it from the response
	resp, err := kc.Do(http.MethodPost, groupsURL.String(), bytes.NewBuffer(groupBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed creating group %q: %s %s", groupName, resp.Status, respBytes)
	}

	return nil
}

func (kc *keycloakClient) CreateUser(username, password string, groups []string) error {
	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users"

	user := map[string]interface{}{
		"username": username,
		"credentials": []map[string]interface{}{
			{
				"temporary": false,
				"type":      "password",
				"value":     password,
			},
		},
		"enabled":       true,
		"emailVerified": true,
		"groups":        groups,
	}

	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Keycloak does not return the object on successful create so there's no need to attempt to retrieve it from the response
	resp, err := kc.Do(http.MethodPost, usersURL.String(), bytes.NewBuffer(userBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed creating user %q: %s %s", username, resp.Status, respBytes)
	}

	return nil
}

func (kc *keycloakClient) ListUsers() ([]map[string]interface{}, error) {
	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users"

	resp, err := kc.Do(http.MethodGet, usersURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing users failed: %s: %s", resp.Status, respBytes)
	}

	users := []map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &users); err != nil {
		return nil, err
	}

	return users, nil
}

func (kc *keycloakClient) UpdateUser(id string, changes map[string]interface{}) error {
	user, err := kc.GetUser(id)
	if err != nil {
		return err
	}

	for k, v := range changes {
		user[k] = v
	}

	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}

	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users/" + id

	resp, err := kc.Do(http.MethodPut, usersURL.String(), bytes.NewBuffer(userBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed updating user %q: %s: %s", id, resp.Status, respBytes)
	}

	return nil
}

func (kc *keycloakClient) GetUser(id string) (map[string]interface{}, error) {
	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users/" + id

	resp, err := kc.Do(http.MethodGet, usersURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	user := map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &user); err != nil {
		return nil, err
	}

	return user, nil
}

func (kc *keycloakClient) ListUserGroups(id string) ([]map[string]interface{}, error) {
	userGroupsURL := *kc.keycloakAdminURL
	userGroupsURL.Path += "/users/" + id + "/groups"

	resp, err := kc.Do(http.MethodGet, userGroupsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	userGroups := []map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &userGroups); err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (kc *keycloakClient) DeleteUserFromGroups(userId string, groupIds ...string) error {
	userGroupsURL := *kc.keycloakAdminURL
	userGroupsURL.Path += "/users/" + userId + "/groups/"

	for _, gid := range groupIds {
		resp, err := kc.Do(http.MethodDelete, userGroupsURL.String()+gid, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed removing group %q from user %q: the server returned %s", gid, userId, resp.Status)
		}
	}

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
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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
	if err = json.Unmarshal(respBytes, &secret); err != nil {
		return "", err
	}

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
