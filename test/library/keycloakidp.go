package library

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// AddKeycloakIDP deploys a Keycloak identity provider for testing and returns the client, IDP name, and cleanup functions.
func AddKeycloakIDP(
	t testing.TB,
	kubeconfig *rest.Config,
	directOIDC bool,
) (kcClient *KeycloakClient, idpName string, cleanups []func()) {
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
		false, // Keycloak works with restricted mode
		"/opt/keycloak/bin/kc.sh", "start-dev",
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
	kcClient = KeycloakClientFor(t, transport, keycloakURL, "master")

	// even though configured via env vars and even though we checked Keycloak reports
	// ready on /health/ready, it still appears that we may need some time to log in properly
	// In resource-constrained CI environments with parallel test execution, Keycloak can take
	// 40-60+ seconds to fully initialize its admin API even after passing readiness probes
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword(ctx, "admin-cli", "", "admin", "password")
		if err != nil {
			t.Logf("failed to authenticate to Keycloak: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	clientList, err := kcClient.ListClients(context.Background())
	require.NoError(t, err)

	var adminClientID, passwdClientID, passwdClientClientID string
	for _, c := range clientList {
		if clientID := c["clientId"].(string); clientID == "admin-cli" {
			adminClientID = c["id"].(string)
		} else if len(c["redirectUris"].([]interface{})) > 0 {
			// just reuse one other client that's already there
			passwdClientID = c["id"].(string)
			passwdClientClientID = clientID
		}

		if len(passwdClientID) > 0 && len(adminClientID) > 0 {
			break
		}
	}

	// change the client's access token timeout just in case we need it for the test
	// Wrap in retry logic as Keycloak may still be unstable after initial authentication
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		err := kcClient.UpdateClientAccessTokenTimeout(ctx, adminClientID, 60*30)
		if err != nil {
			t.Logf("failed to update client access token timeout: %v, retrying", err)
			// Re-authenticate in case the connection was dropped
			if authErr := kcClient.AuthenticatePassword(ctx, "admin-cli", "", "admin", "password"); authErr != nil {
				t.Logf("failed to re-authenticate: %v", authErr)
			}
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	// reauthenticate for a new, longer-lived token
	err = kcClient.AuthenticatePassword(context.Background(), "admin-cli", "", "admin", "password")
	require.NoError(t, err)

	// Regenerate client secret with retry logic for Keycloak stability
	var clientSecret string
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		var err error
		clientSecret, err = kcClient.RegenerateClientSecret(ctx, passwdClientID)
		if err != nil {
			t.Logf("failed to regenerate client secret: %v, retrying", err)
			// Re-authenticate in case the connection was dropped
			if authErr := kcClient.AuthenticatePassword(ctx, "admin-cli", "", "admin", "password"); authErr != nil {
				t.Logf("failed to re-authenticate: %v", authErr)
			}
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	// Create client group mapper with retry logic
	const groupsClaimName = "groups"
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		err := kcClient.CreateClientGroupMapper(ctx, passwdClientID, "test-groups-mapper", groupsClaimName)
		if err != nil {
			t.Logf("failed to create client group mapper: %v, retrying", err)
			// Re-authenticate in case the connection was dropped
			if authErr := kcClient.AuthenticatePassword(ctx, "admin-cli", "", "admin", "password"); authErr != nil {
				t.Logf("failed to re-authenticate: %v", authErr)
			}
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	idpCleans, err := addOIDCIDentityProvider(t,
		kubeClients,
		configClient,
		passwdClientClientID, clientSecret,
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

	return kcClient, openshiftIDPName, cleanups
}

// KeycloakClient provides methods for interacting with a Keycloak server for testing.
type KeycloakClient struct {
	keycloakAdminURL *url.URL
	realm            string
	testT            testing.TB
	client           *http.Client

	accessToken string
	idToken     string
}

// KeycloakClientFor creates a Keycloak REST client for the default (master) realm
// using the supplied transport
func KeycloakClientFor(t testing.TB, transport http.RoundTripper, keycloakURL, keycloakRealm string) *KeycloakClient {
	u, err := url.Parse(keycloakURL)
	require.NoError(t, err)

	u.Path = "/admin/realms/" + keycloakRealm

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	c := &KeycloakClient{
		client:           client,
		keycloakAdminURL: u,
		realm:            keycloakRealm,
		testT:            t,
	}

	return c
}

// AuthenticatePassword authenticates a user with the given username and password against the Keycloak server.
func (kc *KeycloakClient) AuthenticatePassword(ctx context.Context, clientID, clientSecret, name, password string) error {
	data := url.Values{
		"username":   []string{name},
		"password":   []string{password},
		"grant_type": []string{"password"},
		"client_id":  []string{clientID},
		"scope":      []string{"openid"},
	}
	if len(clientSecret) > 0 {
		data.Add("client_secret", clientSecret)
	}

	authReq, err := http.NewRequestWithContext(ctx, http.MethodPost, kc.TokenURL(), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kc.client.Do(authReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check for non-success HTTP status codes before attempting to parse JSON
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	// Verify we received JSON response (Keycloak may return HTML error pages during startup)
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" && !containsIgnoreCase(contentType, "application/json") {
		return fmt.Errorf("expected JSON response but got Content-Type %q: %s", contentType, string(respBytes))
	}

	authResp := map[string]any{}
	if err := json.Unmarshal(respBytes, &authResp); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w (response body: %s)", err, string(respBytes))
	}

	accessToken, err := retrieveValue("access_token", authResp)
	if err != nil {
		return err
	}
	kc.accessToken = accessToken

	idToken, err := retrieveValue("id_token", authResp)
	if err != nil {
		return nil
	}
	kc.idToken = idToken

	return nil
}

// Tokens returns the current access token and ID token.
func (kc *KeycloakClient) Tokens() (accessToken, idToken string) {
	return kc.accessToken, kc.idToken
	// CreateClientGroupMapper creates a group membership mapper for the specified client.
}

// CreateClientGroupMapper creates a group membership mapper for the specified client.
func (kc *KeycloakClient) CreateClientGroupMapper(ctx context.Context, clientID, mapperName, groupsClaimName string) error {
	mappersURL := *kc.keycloakAdminURL
	mappersURL.Path += "/clients/" + clientID + "/protocol-mappers/models"

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
	resp, err := kc.do(ctx, http.MethodPost, mappersURL.String(), bytes.NewBuffer(mapperBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed creating mapper %q: %s %s", mapperName, resp.Status, respBytes)
	}

	// CreateGroup creates a new group with the given name.
	return nil
}

// CreateGroup creates a new group with the given name.
func (kc *KeycloakClient) CreateGroup(ctx context.Context, groupName string) error {
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
	resp, err := kc.do(ctx, http.MethodPost, groupsURL.String(), bytes.NewBuffer(groupBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed creating group %q: %s %s", groupName, resp.Status, respBytes)
	}
	// ListGroups returns all groups in the realm.
	return nil
}

// ListGroups returns all groups in the realm.
func (kc *KeycloakClient) ListGroups(ctx context.Context) ([]map[string]interface{}, error) {
	allGroups := []map[string]interface{}{}
	first := 0
	max := 100 // Keycloak default page size

	for {
		groupsURL := *kc.keycloakAdminURL
		groupsURL.Path += "/groups"
		q := groupsURL.Query()
		q.Set("first", fmt.Sprintf("%d", first))
		q.Set("max", fmt.Sprintf("%d", max))
		groupsURL.RawQuery = q.Encode()

		resp, err := kc.do(ctx, http.MethodGet, groupsURL.String(), nil)
		if err != nil {
			return nil, err
		}

		respBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("listing groups failed: %s: %s", resp.Status, respBytes)
		}

		groups := []map[string]interface{}{}
		if err := json.Unmarshal(respBytes, &groups); err != nil {
			return nil, err
		}

		if len(groups) == 0 {
			break
		}

		allGroups = append(allGroups, groups...)
		first += len(groups)
		// DeleteGroup deletes the group with the given name.
	}

	return allGroups, nil
}

// DeleteGroup deletes the group with the given name.
func (kc *KeycloakClient) DeleteGroup(ctx context.Context, groupName string) error {
	// First, find the group by name to get its ID
	groups, err := kc.ListGroups(ctx)
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}

	var groupID string
	for _, group := range groups {
		if name, ok := group["name"].(string); ok && name == groupName {
			if id, ok := group["id"].(string); ok {
				groupID = id
				break
			}
		}
	}

	if groupID == "" {
		// Group not found - not an error, it may have already been deleted
		return nil
	}

	groupsURL := *kc.keycloakAdminURL
	groupsURL.Path += "/groups/" + groupID

	resp, err := kc.do(ctx, http.MethodDelete, groupsURL.String(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed deleting group %q (ID: %s): %s %s", groupName, groupID, resp.Status, respBytes)
	}

	return nil
}

// CreateUser creates a new user with the given details.
func (kc *KeycloakClient) CreateUser(ctx context.Context, username, email, password string, groups []string, extraFields map[string]string) error {
	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users"

	user := map[string]interface{}{
		"username": username,
		"email":    fmt.Sprintf("%s@test.dev", username),
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

	for k, v := range extraFields {
		user[k] = v
	}

	if len(email) > 0 {
		user["email"] = email
	}

	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Keycloak does not return the object on successful create so there's no need to attempt to retrieve it from the response
	resp, err := kc.do(ctx, http.MethodPost, usersURL.String(), bytes.NewBuffer(userBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed creating user %q: %s %s", username, resp.Status, respBytes)
	}

	return nil
}

// DeleteUser deletes the user with the given username.
func (kc *KeycloakClient) DeleteUser(ctx context.Context, username string) error {
	// First, find the user by username to get its ID
	users, err := kc.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	var userID string
	for _, user := range users {
		if name, ok := user["username"].(string); ok && name == username {
			if id, ok := user["id"].(string); ok {
				userID = id
				break
			}
		}
	}

	if userID == "" {
		// User not found - not an error, it may have already been deleted
		return nil
	}

	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users/" + userID

	resp, err := kc.do(ctx, http.MethodDelete, usersURL.String(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed deleting user %q (ID: %s): %s %s", username, userID, resp.Status, respBytes)
	}

	return nil
}

// ListUsers returns all users in the realm.
func (kc *KeycloakClient) ListUsers(ctx context.Context) ([]map[string]interface{}, error) {
	allUsers := []map[string]interface{}{}
	first := 0
	max := 100 // Keycloak default page size

	for {
		usersURL := *kc.keycloakAdminURL
		usersURL.Path += "/users"
		q := usersURL.Query()
		q.Set("first", fmt.Sprintf("%d", first))
		q.Set("max", fmt.Sprintf("%d", max))
		usersURL.RawQuery = q.Encode()

		resp, err := kc.do(ctx, http.MethodGet, usersURL.String(), nil)
		if err != nil {
			return nil, err
		}

		respBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
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

		if len(users) == 0 {
			break
		}

		allUsers = append(allUsers, users...)
		first += len(users)
	}

	return allUsers, nil
}

// UpdateUser updates the user with the given ID using the specified changes.
func (kc *KeycloakClient) UpdateUser(ctx context.Context, id string, changes map[string]interface{}) error {
	user, err := kc.GetUser(ctx, id)
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

	resp, err := kc.do(ctx, http.MethodPut, usersURL.String(), bytes.NewBuffer(userBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed updating user %q: %s: %s", id, resp.Status, respBytes)
	}

	return nil
}

// GetUser returns the user with the given ID.
func (kc *KeycloakClient) GetUser(ctx context.Context, id string) (map[string]interface{}, error) {
	usersURL := *kc.keycloakAdminURL
	usersURL.Path += "/users/" + id

	resp, err := kc.do(ctx, http.MethodGet, usersURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	user := map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &user); err != nil {
		return nil, err
	}

	return user, nil
}

// ListUserGroups returns all groups that the user with the given ID belongs to.
func (kc *KeycloakClient) ListUserGroups(ctx context.Context, id string) ([]map[string]interface{}, error) {
	userGroupsURL := *kc.keycloakAdminURL
	userGroupsURL.Path += "/users/" + id + "/groups"

	resp, err := kc.do(ctx, http.MethodGet, userGroupsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	userGroups := []map[string]interface{}{}
	if err := json.Unmarshal(respBytes, &userGroups); err != nil {
		return nil, err
	}

	return userGroups, nil
}

// DeleteUser deletes the user with the given username.
// DeleteUserFromGroups removes the user from the specified groups.
func (kc *KeycloakClient) DeleteUserFromGroups(ctx context.Context, userID string, groupIds ...string) error {
	userGroupsURL := *kc.keycloakAdminURL
	userGroupsURL.Path += "/users/" + userID + "/groups/"

	for _, gid := range groupIds {
		resp, err := kc.do(ctx, http.MethodDelete, userGroupsURL.String()+gid, nil)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			resp.Body.Close()
			return fmt.Errorf("failed removing group %q from user %q: the server returned %s", gid, userID, resp.Status)
		}
		resp.Body.Close()
	}

	return nil
}

// UpdateClientAccessTokenTimeout updates the timeout for a client of the given id
// timeout is a timeout in seconds
func (kc *KeycloakClient) UpdateClientAccessTokenTimeout(ctx context.Context, id string, timeout int32) error {
	changes := map[string]interface{}{
		"attributes": map[string]interface{}{
			"access.token.lifespan": timeout,
		},
	}

	return kc.UpdateClient(ctx, id, changes)
}

// UpdateClientDirectAccessGrantsEnabled updates the `directAccessGrantsEnabled`
// attribute of the client which influences whether the password grant is allowed
// via the client or not
func (kc *KeycloakClient) UpdateClientDirectAccessGrantsEnabled(ctx context.Context, id string, allow bool) error {
	changes := map[string]interface{}{
		"directAccessGrantsEnabled": allow,
	}

	return kc.UpdateClient(ctx, id, changes)
}

// UpdateClient updates the client with the given ID using the specified fields.
func (kc *KeycloakClient) UpdateClient(ctx context.Context, id string, changedFields map[string]interface{}) error {
	client, err := kc.GetClient(ctx, id)
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
	resp, err := kc.do(ctx, http.MethodPut, clientsURL.String(), bytes.NewBuffer(clientBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed updating client %q: %s: %s", id, resp.Status, respBytes)
	}

	return nil
}

// GetClient retrieves a client based on its id (NOTE: id != clientID)
func (kc *KeycloakClient) GetClient(ctx context.Context, id string) (map[string]interface{}, error) {
	clientsURL := *kc.keycloakAdminURL
	clientsURL.Path += "/clients/" + id

	resp, err := kc.do(ctx, http.MethodGet, clientsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// GetClientByClientID returns the client with the given client ID.
	respBytes, err := io.ReadAll(resp.Body)
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

// GetClientByClientID returns the client with the given client ID.
func (kc *KeycloakClient) GetClientByClientID(ctx context.Context, clientID string) (map[string]interface{}, error) {
	// ListClients returns all clients in the realm.
	clients, err := kc.ListClients(ctx)
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
func (kc *KeycloakClient) ListClients(ctx context.Context) ([]map[string]interface{}, error) {
	clientsURL := *kc.keycloakAdminURL
	clientsURL.Path += "/clients"

	resp, err := kc.do(ctx, http.MethodGet, clientsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	// RegenerateClientSecret regenerates and returns the client secret for the client with the given ID.
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
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

// RegenerateClientSecret regenerates and returns the client secret for the client with the given ID.
func (kc *KeycloakClient) RegenerateClientSecret(ctx context.Context, id string) (string, error) {
	clientRegenURL := *kc.keycloakAdminURL
	clientRegenURL.Path += "/clients/" + id + "/client-secret"

	resp, err := kc.do(ctx, http.MethodPost, clientRegenURL.String(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
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

func (kc *KeycloakClient) do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	if len(kc.accessToken) == 0 {
		return nil, fmt.Errorf("authenticate first")
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", kc.accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return kc.client.Do(req)
}

// AdminURL returns the Keycloak admin URL.
func (kc *KeycloakClient) AdminURL() string {
	return kc.keycloakAdminURL.String()
}

// TokenURL returns the Keycloak token endpoint URL.
func (kc *KeycloakClient) TokenURL() string {
	authURL := *kc.keycloakAdminURL
	authURL.Path = "/realms/" + kc.realm + "/protocol/openid-connect/token"

	return authURL.String()
}

// IssuerURL returns the Keycloak OIDC issuer URL.
func (kc *KeycloakClient) IssuerURL() string {
	issuerURL := *kc.keycloakAdminURL
	issuerURL.Path = "/realms/" + kc.realm

	return issuerURL.String()
}

func retrieveValue(field string, sourceMap map[string]any) (string, error) {
	value, ok := sourceMap[field].(string)
	if !ok || len(value) == 0 {
		errorMessage := fmt.Sprintf("failed to retrieve %s", field)
		if serverErrorMessage, ok := sourceMap["error"]; ok {
			errorMessage = fmt.Sprintf("%s. Server error was: %s", errorMessage, serverErrorMessage)
			if serverErrorDescription, ok := sourceMap["error_description"]; ok {
				errorMessage = fmt.Sprintf("%s - %s", errorMessage, serverErrorDescription)
			}
		}
		return "", errors.New(errorMessage)
	}

	return value, nil
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
