package library

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"

	"github.com/stretchr/testify/require"
)

func AddGitlabIDP( // TODO: possibly make this be a wrapper to a function to simplify cleanup
	t *testing.T,
	kubeconfig *rest.Config,
) (idpURL, idpName string, cleanups []func()) {
	kubeClients, err := kubernetes.NewForConfig(kubeconfig)
	require.NoError(t, err)

	routeClient, err := routev1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	configclients, err := configv1client.NewForConfig(kubeconfig)
	require.NoError(t, err)

	nsName, gitlabHost, cleanup := deployPod(t, kubeClients, routeClient,
		"gitlab",
		"docker.io/gitlab/gitlab-ce:13.8.4-ce.0",
		[]corev1.EnvVar{
			// configure password for GitLab root user
			{Name: "GITLAB_OMNIBUS_CONFIG", Value: "gitlab_rails['initial_root_password']='password';"},
		},
		80,
		443,
		[]corev1.Volume{
			{
				Name: "configdir",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		},
		[]corev1.VolumeMount{
			{
				Name:      "configdir",
				SubPath:   "gitlab/config",
				MountPath: "/etc/gitlab",
			},
			{
				Name:      "configdir",
				SubPath:   "gitlab/logs",
				MountPath: "/var/log/gitlab",
			},
			{
				Name:      "configdir",
				SubPath:   "gitlab/data",
				MountPath: "/var/opt/gitlab",
			},
		},
		corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				// it's a bit resource-heavy, it will probably eat more during start-up
				// max observed cpu: 1420m
				// max observed memory: 2001Mi
				// but that's more than our devel clusters provide, let's just request some minimum
				// and have the pod eat more
				"cpu":    resource.MustParse("500m"),
				"memory": resource.MustParse("1500Mi"),
			},
		},
		nil,
		nil,
		false,
	)
	cleanups = []func(){cleanup}

	gitlabURL := "https://" + gitlabHost
	transport, err := rest.TransportFor(kubeconfig)
	defer func() {
		if err != nil {
			for _, c := range cleanups {
				c()
			}
		}
	}()
	require.NoError(t, err)

	gitlabClient := GitLabClientFor(t, transport, gitlabURL)

	// TODO: future us might try to configure whitelist IPs so that we can configure
	// health and readiness probes via gitlab's /-/health and /-/readiness endpoints
	WaitForHTTPStatus(t, 10*time.Minute, gitlabClient.client, gitlabClient.gitlabURL.String(), 200)
	err = gitlabClient.PasswordAuthenticate("root", "password")
	require.NoError(t, err, "failed to login as root")

	openshiftIDPName := fmt.Sprintf("gitlab-test-%s", nsName)

	app, err := gitlabClient.CreateApplication(
		"openshift-non-confidential",
		[]string{fmt.Sprintf("https://oauth.server.ip/oauth2callback/%s", openshiftIDPName)}, // FIXME: a real redirect URI
		[]string{"openid", "profile", "email"},
		false)

	appID := app["application_id"].(string)
	appSecret := app["secret"].(string)

	idpCleanups, err := addOIDCIDentityProvider(t, kubeClients, configclients, appID, appSecret, openshiftIDPName, gitlabURL, configv1.OpenIDClaims{}, false)
	require.NoError(t, err)

	return gitlabURL, openshiftIDPName, append(cleanups, idpCleanups...)
}

type gitlabClient struct {
	gitlabURL   *url.URL
	testContext *testing.T
	token       string
	client      *http.Client
}

func GitLabClientFor(t *testing.T, transport http.RoundTripper, gitlabURL string) *gitlabClient {
	u, err := url.Parse(gitlabURL)
	require.NoError(t, err)

	client := &http.Client{
		Transport: transport,
	}

	c := &gitlabClient{
		client:      client,
		gitlabURL:   u,
		testContext: t,
	}

	return c
}

func (c *gitlabClient) PasswordAuthenticate(user, password string) error {
	params := url.Values{
		"grant_type": []string{"password"},
		"username":   []string{user},
		"password":   []string{password},
	}
	encodedBody := params.Encode()

	tokenURL := *c.gitlabURL
	tokenURL.Path = "/oauth/token"

	req, err := http.NewRequest(http.MethodPost, tokenURL.String(), bytes.NewBufferString(encodedBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	require.NoError(c.testContext, err, "error attempting to login as root to GitLab")
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("gitlab login failed for user %s: %s ", user, respBytes)
	}

	tokenResponse := map[string]interface{}{}
	err = json.Unmarshal(respBytes, &tokenResponse)
	if err != nil {
		return err
	}

	t, ok := tokenResponse["access_token"]
	tokenString := fmt.Sprintf("%v", t)
	if !ok || len(tokenString) == 0 {
		c.testContext.Fatalf("the token response does not contain any access token: %v", tokenResponse)
	}

	c.token = tokenString
	return nil
}

func (c *gitlabClient) createResource(endpoint string, res map[string]interface{}) (map[string]interface{}, error) {
	resourceJSON, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize object: %w", err)
	}

	reqURL := *c.gitlabURL
	reqURL.Path = fmt.Sprintf("/api/v4/%s", endpoint)
	req, err := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewBuffer(resourceJSON))
	require.NoError(c.testContext, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if len(c.token) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}

	resp, err := c.client.Do(req)
	if err != nil { // return err to be handled during specific resource creation
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 201: // Created
		respMap := map[string]interface{}{}
		err = json.NewDecoder(resp.Body).Decode(&respMap)
		if err != nil {
			return nil, err
		}

		return respMap, nil
	default:
		reqDump, _ := httputil.DumpRequest(req, true)
		c.testContext.Logf("failed request: %s", reqDump)

		respBody, _ := ioutil.ReadAll(resp.Body)
		c.testContext.Logf("response: %s", respBody)

		return nil, fmt.Errorf("unhandled status: %q", resp.Status)

	}
}

func (c *gitlabClient) CreateUser(username, password string, isAdmin bool) (map[string]interface{}, error) {
	user := map[string]interface{}{
		"username": username,
		"name":     username,
		"password": password, // min length 8!
		"email":    fmt.Sprintf("%s@userparadise.up", username),
		"admin":    isAdmin,
	}

	return c.createResource("users", user)
}

func (c *gitlabClient) CreateApplication(name string, redirectURIs, scopes []string, confidential bool) (map[string]interface{}, error) {
	application := map[string]interface{}{
		"name":         name,
		"redirect_uri": strings.Join(redirectURIs, "\n"),
		"scopes":       strings.Join(scopes, ","),
		"confidential": confidential,
	}

	return c.createResource("applications", application)
}
