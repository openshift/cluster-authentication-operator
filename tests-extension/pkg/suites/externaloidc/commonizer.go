package externaloidc

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	g "github.com/onsi/ginkgo/v2"
	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/library-go/pkg/operator/condition"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/openshift/origin/test/extended/util/operator"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/pod-security-admission/api"

	"github.com/openshift/origin/test/extended/util/image"
)

const testID = "cao-oidc-e2e"

var (
	Username          = fmt.Sprintf("user-%s", testID)
	Password          = fmt.Sprintf("password-%s", testID)
	Group             = fmt.Sprintf("ocp-test-%s-group", testID)
	KeycloakNamespace = fmt.Sprintf("oidc-keycloak-%s", testID)
	OIDCClientSecret  = fmt.Sprintf("openshift-console-oidc-client-secret-%s", testID)
)

type ExtraFunc func(context.Context, *Commonizer) error

type Commonizer struct {
	OriginalAuthentication *configv1.Authentication
	Client                 *exutil.CLI
	KeycloakClient         *KeycloakClient
	beforeAllExtras        ExtraFunc
}

func NewCommonizer(beforeAllExtras ExtraFunc) *Commonizer {
	return &Commonizer{
		beforeAllExtras: beforeAllExtras,
	}
}

func (c *Commonizer) SuiteBeforeAll() error {
	oc := exutil.NewCLIWithoutNamespace("oidc-e2e")
	oc.KubeFramework().NamespacePodSecurityLevel = api.LevelPrivileged
	oc.SetNamespace("oidc-e2e")

	c.Client = oc

	var err error
	ctx := context.TODO()

	image.InitializeImages(os.Getenv("KUBE_TEST_REPO"))

	// waitTime is in minutes - set to 30 minute wait for cluster operators to settle before starting tests.
	err = operator.WaitForOperatorsToSettle(ctx, oc.AdminConfigClient(), 30)
	if err != nil {
		return fmt.Errorf("waiting for cluster operators to settle: %w", err)
	}

	err = DeployKeycloak(ctx, oc, KeycloakNamespace, g.GinkgoLogr)
	if err != nil {
		return fmt.Errorf("deploying keycloak: %w", err)
	}

	kcURL, err := AdmittedURLForRoute(ctx, oc, KeycloakResourceName, KeycloakNamespace)
	if err != nil {
		return fmt.Errorf("getting admitted route URL for keycloak: %w", err)
	}

	keycloakCli, err := KeycloakClientFor(kcURL)
	if err != nil {
		return fmt.Errorf("creating keycloak client: %w", err)
	}

	// First authenticate as the admin keycloak user so we can add new groups and users
	err = keycloakCli.Authenticate("admin-cli", KeycloakAdminUsername, KeycloakAdminPassword)
	if err != nil {
		return fmt.Errorf("authenticating as keycloak admin user: %w", err)
	}

	err = keycloakCli.ConfigureClient("admin-cli")
	if err != nil {
		return fmt.Errorf("configuring keycloak client: %w", err)
	}

	err = keycloakCli.CreateGroup(Group)
	if err != nil {
		return fmt.Errorf("creating keycloak group: %w", err)
	}

	err = keycloakCli.CreateUser(Username, Password, Group)
	if err != nil {
		return fmt.Errorf("creating keycloak user: %w", err)
	}

	c.KeycloakClient = keycloakCli

	// create a dummy oidc client secret for the console to consume
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OIDCClientSecret,
			Namespace: "openshift-config",
		},
		Data: map[string][]byte{
			"clientSecret": []byte(`a-secret-value`),
		},
	}
	_, err = oc.AdminKubeClient().CoreV1().Secrets("openshift-config").Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating oidc client secret: %w", err)
	}

	err = c.beforeAllExtras(ctx, c)
	if err != nil {
		return fmt.Errorf("performing extra before all steps: %w", err)
	}

	return nil
}

func (c *Commonizer) SuiteAfterAll() error {
	ctx := context.TODO()
	oc := c.Client

	err, modified := resetAuthentication(ctx, oc, c.OriginalAuthentication)
	if err != nil {
		return fmt.Errorf("resetting authentication: %w", err)
	}

	// Only if we modified the Authentication resource during the reset should we wait for a rollout
	if modified {
		if err := waitForRollout(ctx, oc); err != nil {
			return fmt.Errorf("waiting for reset authentication rollout: %w", err)
		}
	}

	err = TeardownKeycloak(ctx, oc, KeycloakNamespace)
	if err != nil {
		return fmt.Errorf("tearing down keycloak: %w", err)
	}

	return nil
}

func ConfigureSuiteBeforeAllExtra() ExtraFunc {
	return func(ctx context.Context, c *Commonizer) error {
		original, _, err := ConfigureOIDCAuthentication(ctx, c.Client, KeycloakNamespace, OIDCClientSecret, nil)
		if err != nil {
			return fmt.Errorf("configuring OIDC authentication: %w", err)
		}

		c.OriginalAuthentication = original

		err = waitForRollout(ctx, c.Client)
		if err != nil {
			return fmt.Errorf("waiting for rollout: %w", err)
		}

		return nil
	}
}

func RevertSuiteBeforeAllExtra() ExtraFunc {
	return func(ctx context.Context, c *Commonizer) error {
		original, _, err := ConfigureOIDCAuthentication(ctx, c.Client, KeycloakNamespace, OIDCClientSecret, nil)
		if err != nil {
			return fmt.Errorf("configuring OIDC authentication: %w", err)
		}

		c.OriginalAuthentication = original

		err = waitForRollout(ctx, c.Client)
		if err != nil {
			return fmt.Errorf("waiting for rollout: %w", err)
		}

		// Wait until we can authenticate using the configured external IdP
		timeoutCtx, cancel := context.WithDeadline(ctx, time.Now().Add(5*time.Minute))
		defer cancel()
		err = wait.PollUntilContextCancel(timeoutCtx, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			copiedOC := *c.Client
			tokenOC := copiedOC.WithToken(c.KeycloakClient.AccessToken())

			_, err := tokenOC.KubeClient().AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("%s-info", Username),
				},
			}, metav1.CreateOptions{})
			if err != nil {
				log.Println("error creating selfsubjectreview: %v . continuing to wait for desired state...", err)
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			return fmt.Errorf("waiting to authenticate with external idp: %w", err)
		}

		err, modified := resetAuthentication(ctx, c.Client, c.OriginalAuthentication)
		if err != nil {
			return fmt.Errorf("resetting authentication: %w", err)
		}

		if modified {
			if err := waitForRollout(ctx, c.Client); err != nil {
				return fmt.Errorf("waiting for reset authenticate rollout: %w", err)
			}
		}

		return nil
	}
}

func UIDExtraSuiteBeforeAllExtra() ExtraFunc {
	return func(ctx context.Context, c *Commonizer) error {
		original, _, err := ConfigureOIDCAuthentication(ctx, c.Client, KeycloakNamespace, OIDCClientSecret, func(o *configv1.OIDCProvider) {
			o.ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
				Expression: "claims.preferred_username.upperAscii()",
			}

			o.ClaimMappings.Extra = []configv1.ExtraMapping{
				{
					Key:             "payload/test",
					ValueExpression: "claims.email + 'extra'",
				},
			}
		})
		if err != nil {
			return fmt.Errorf("configuring OIDC authentication: %w", err)
		}

		c.OriginalAuthentication = original

		err = waitForRollout(ctx, c.Client)
		if err != nil {
			return fmt.Errorf("waiting for rollout: %w", err)
		}

		return nil
	}
}

func ConfigureOIDCAuthentication(ctx context.Context, client *exutil.CLI, keycloakNS, oidcClientSecret string, modifier func(*configv1.OIDCProvider)) (*configv1.Authentication, *configv1.Authentication, error) {
	authConfig, err := client.AdminConfigClient().ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("getting authentications.config.openshift.io/cluster: %w", err)
	}

	original := authConfig.DeepCopy()
	modified := authConfig.DeepCopy()

	oidcProvider, err := generateOIDCProvider(ctx, client, keycloakNS, oidcClientSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("generating OIDC provider: %w", err)
	}

	if modifier != nil {
		modifier(oidcProvider)
	}

	modified.Spec.Type = configv1.AuthenticationTypeOIDC
	modified.Spec.WebhookTokenAuthenticator = nil
	modified.Spec.OIDCProviders = []configv1.OIDCProvider{*oidcProvider}

	modified, err = client.AdminConfigClient().ConfigV1().Authentications().Update(ctx, modified, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	return original, modified, nil
}

func generateOIDCProvider(ctx context.Context, client *exutil.CLI, namespace, oidcClientSecret string) (*configv1.OIDCProvider, error) {
	idpName := "keycloak"
	caBundle := "keycloak-ca"
	audiences := []configv1.TokenAudience{
		"admin-cli",
	}
	usernameClaim := "email"
	groupsClaim := "groups"

	idpUrl, err := AdmittedURLForRoute(ctx, client, KeycloakResourceName, namespace)
	if err != nil {
		return nil, fmt.Errorf("getting issuer URL: %w", err)
	}

	return &configv1.OIDCProvider{
		Name: idpName,
		Issuer: configv1.TokenIssuer{
			URL: fmt.Sprintf("%s/realms/master", idpUrl),
			CertificateAuthority: configv1.ConfigMapNameReference{
				Name: caBundle,
			},
			Audiences: audiences,
		},
		ClaimMappings: configv1.TokenClaimMappings{
			Username: configv1.UsernameClaimMapping{
				Claim: usernameClaim,
			},
			Groups: configv1.PrefixedClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: groupsClaim,
				},
			},
		},
		// while this config is not required for the tests in this suite, if omitted
		// the console-operator will go Degraded; since we're currently running these
		// tests in clusters where the Console is installed, we provide this config
		// to avoid breaking cluster operator monitor tests
		OIDCClients: []configv1.OIDCClientConfig{
			{
				ComponentName:      "console",
				ComponentNamespace: "openshift-console",
				ClientID:           "openshift-console-oidc-client",
				ClientSecret: configv1.SecretNameReference{
					Name: oidcClientSecret,
				},
			},
		},
	}, nil
}

func AdmittedURLForRoute(ctx context.Context, client *exutil.CLI, routeName, namespace string) (string, error) {
	var admittedURL string

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	err := wait.PollUntilContextCancel(timeoutCtx, 1*time.Second, true, func(ctx context.Context) (bool, error) {
		route, err := client.AdminRouteClient().RouteV1().Routes(namespace).Get(ctx, routeName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		for _, ingress := range route.Status.Ingress {
			for _, condition := range ingress.Conditions {
				if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
					admittedURL = ingress.Host
					return true, nil
				}
			}
		}

		return false, fmt.Errorf("no admitted ingress for route %q", route.Name)
	})
	return fmt.Sprintf("https://%s", admittedURL), err
}

func resetAuthentication(ctx context.Context, client *exutil.CLI, original *configv1.Authentication) (error, bool) {
	if original == nil {
		return nil, false
	}

	modified := false
	timeoutCtx, cancel := context.WithDeadline(ctx, time.Now().Add(5*time.Minute))
	defer cancel()
	cli := client.AdminConfigClient().ConfigV1().Authentications()
	err := wait.PollUntilContextCancel(timeoutCtx, 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
		current, err := cli.Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("getting the current authentications.config.openshift.io/cluster: %w", err)
		}

		if equality.Semantic.DeepEqual(current.Spec, original.Spec) {
			return true, nil
		}

		current.Spec = original.Spec
		modified = true

		_, err = cli.Update(ctx, current, metav1.UpdateOptions{})
		if err != nil {
			// Only log the error so we continue to retry until the context has timed out
			g.GinkgoLogr.Error(err, "updating authentication resource")
			return false, nil
		}

		return true, nil
	})

	return err, modified
}

func waitForRollout(ctx context.Context, client *exutil.CLI) error {
	kasCli := client.AdminOperatorClient().OperatorV1().KubeAPIServers()

	// First wait for KAS NodeInstallerProgressing condition to flip to "True".
	// This means that the KAS-O has successfully started being configured
	// with our auth resource changes.
	timeoutCtx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Minute))
	defer cancel()
	err := wait.PollUntilContextCancel(timeoutCtx, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		err := checkKubeAPIServerCondition(ctx, kasCli, condition.NodeInstallerProgressingConditionType, operatorv1.ConditionTrue)
		if err != nil {
			log.Println("error checking kube-apiserver condition: %v . continuing to wait for desired state...", err)
			return false, nil
		}
		return true, nil
	})

	// waitTime is in minutes - set to 50 minute wait for cluster operators to settle
	// Usually, it doesn't take nearly an hour for cluster operators to settle
	// but due to the disruptive nature of how we are testing here means we _may_
	// encounter scenarios where the KAS is undergoing multiple revision rollouts
	// in succession. The worst case we've seen is 2 back-to-back revision rollouts
	// which lead to the cluster-authentication-operator being unavailable for ~35-45
	// minutes as it waits for the KAS to finish rolling out so it can begin
	// doing whatever configurations it needs to.
	err = operator.WaitForOperatorsToSettle(ctx, client.AdminConfigClient(), 50)
	if err != nil {
		return fmt.Errorf("waiting for cluster operators to settle: %w", err)
	}

	return nil
}

// checkKubeAPIServerCondition is a utility function to check that the KubeAPIServer
// resource on the cluster has a status condition type set with the expected
// condition status. If it does not, it returns an error. If it does, it returns <nil>.
func checkKubeAPIServerCondition(ctx context.Context, kasCli operatorv1client.KubeAPIServerInterface, conditionType string, conditionStatus operatorv1.ConditionStatus) error {
	kas, err := kasCli.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting KAS: %w", err)
	}

	found := false
	nipCond := operatorv1.OperatorCondition{}
	for _, cond := range kas.Status.Conditions {
		if cond.Type == condition.NodeInstallerProgressingConditionType {
			found = true
			nipCond = cond
			break
		}
	}

	if !found {
		return fmt.Errorf("no condition %q found in KAS status conditions", conditionType)
	}

	if nipCond.Status != conditionStatus {
		return fmt.Errorf("condition %q expected to have status %q, but has status %q instead. Full condition: %v", conditionType, conditionStatus, nipCond.Status, nipCond)
	}

	return nil
}
