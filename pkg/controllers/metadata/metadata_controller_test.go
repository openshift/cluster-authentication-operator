package metadata

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	common "github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	clocktesting "k8s.io/utils/clock/testing"
)

type fakeAuthenticationConfigChecker struct {
	oidcAvailable   bool
	oidcError       error
	authConfig      *configv1.Authentication
	authConfigError error
	authConfigCalls int
}

func (c *fakeAuthenticationConfigChecker) OIDCAvailable() (bool, error) {
	return c.oidcAvailable, c.oidcError
}

func (c *fakeAuthenticationConfigChecker) AuthConfig() (*configv1.Authentication, error) {
	c.authConfigCalls++
	return c.authConfig, c.authConfigError
}

type staticRouteClient struct {
	routeclient.RouteInterface
	route *routev1.Route
}

type recordingOperatorClient struct {
	v1helpers.OperatorClient
	applyError error
	applyCalls int
}

type recordingAuthenticationClient struct {
	configv1client.AuthenticationInterface
	statusUpdateContext context.Context
}

func (c *recordingAuthenticationClient) UpdateStatus(ctx context.Context, authentication *configv1.Authentication, opts metav1.UpdateOptions) (*configv1.Authentication, error) {
	c.statusUpdateContext = ctx
	return c.AuthenticationInterface.UpdateStatus(ctx, authentication, opts)
}

func (c *recordingOperatorClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.OperatorStatusApplyConfiguration) error {
	c.applyCalls++
	if c.applyError != nil {
		return c.applyError
	}
	return c.OperatorClient.ApplyOperatorStatus(ctx, fieldManager, status)
}

func (c staticRouteClient) Get(context.Context, string, metav1.GetOptions) (*routev1.Route, error) {
	return c.route, nil
}

func TestMetadataControllerSync(t *testing.T) {
	deleteError := stderrors.New("config map deletion failed")
	configMapGetError := stderrors.New("config map lookup failed")
	statusUpdateError := stderrors.New("authentication status update failed")
	getAuthConfigError := stderrors.New("authentication config lister failed")
	availabilityError := stderrors.New("OIDC availability check failed")
	conditionApplyError := stderrors.New("operator status apply failed")

	authentication := func(authType configv1.AuthenticationType, metadataName string) *configv1.Authentication {
		return &configv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       configv1.AuthenticationSpec{Type: authType},
			Status: configv1.AuthenticationStatus{
				IntegratedOAuthMetadata: configv1.ConfigMapNameReference{Name: metadataName},
			},
		}
	}

	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: "oauth-openshift", Namespace: "openshift-authentication"},
		Status:     routev1.RouteStatus{Ingress: []routev1.RouteIngress{{Host: "oauth.apps.example.com"}}},
	}

	tests := []struct {
		name                           string
		oidcAvailable                  bool
		oidcError                      error
		authentication                 *configv1.Authentication
		liveAuthentication             *configv1.Authentication
		authConfigError                error
		operandPresent                 bool
		pendingDeletion                bool
		deleteError                    error
		configMapGetError              error
		statusUpdateError              error
		operatorStatusError            error
		route                          *routev1.Route
		wantMetadataName               string
		wantDeleteAttempt              bool
		wantStatusUpdate               bool
		wantAuthConfigCalls            int
		assertOperatorStatusApplyCalls bool
		wantOperatorStatusApplyCalls   int
		assertStatusUpdateLogsDisabled bool
		wantSyncError                  bool
		wantOperationError             error
		wantConditionError             error
		wantDegradedReason             string
	}{
		{
			name:                           "clears integrated OAuth metadata after OIDC operands are removed",
			oidcAvailable:                  true,
			authentication:                 authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			operandPresent:                 true,
			wantDeleteAttempt:              true,
			wantStatusUpdate:               true,
			wantAuthConfigCalls:            1,
			assertStatusUpdateLogsDisabled: true,
		},
		{
			name:               "reports and retries operand removal failure before updating status",
			oidcAvailable:      true,
			authentication:     authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			operandPresent:     true,
			deleteError:        deleteError,
			wantMetadataName:   "oauth-openshift",
			wantDeleteAttempt:  true,
			wantSyncError:      true,
			wantOperationError: deleteError,
			wantDegradedReason: "OperandRemovalFailed",
		},
		{
			name:                           "waits for metadata ConfigMap deletion before clearing the reference",
			oidcAvailable:                  true,
			authentication:                 authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			operandPresent:                 true,
			pendingDeletion:                true,
			wantMetadataName:               "oauth-openshift",
			wantDeleteAttempt:              true,
			assertOperatorStatusApplyCalls: true,
			wantOperatorStatusApplyCalls:   0,
			wantSyncError:                  true,
			wantOperationError:             factory.SyntheticRequeueError,
		},
		{
			name:               "reports metadata ConfigMap lookup failure after deletion request",
			oidcAvailable:      true,
			authentication:     authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			operandPresent:     true,
			configMapGetError:  configMapGetError,
			wantMetadataName:   "oauth-openshift",
			wantDeleteAttempt:  true,
			wantSyncError:      true,
			wantOperationError: configMapGetError,
			wantDegradedReason: "OperandRemovalFailed",
		},
		{
			name:                "reports and retries authentication config read failure",
			oidcAvailable:       true,
			authentication:      authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			authConfigError:     getAuthConfigError,
			wantMetadataName:    "oauth-openshift",
			wantAuthConfigCalls: 1,
			wantSyncError:       true,
			wantOperationError:  getAuthConfigError,
			wantDegradedReason:  "FailedGet",
		},
		{
			name:               "reports Authentication read failure from OIDC availability check",
			oidcError:          &common.AuthenticationConfigLookupError{Err: getAuthConfigError},
			authentication:     authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			wantMetadataName:   "oauth-openshift",
			wantSyncError:      true,
			wantOperationError: getAuthConfigError,
			wantDegradedReason: "FailedGet",
		},
		{
			name:                           "preserves unrelated OIDC availability errors",
			oidcError:                      availabilityError,
			authentication:                 authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			authConfigError:                getAuthConfigError,
			wantMetadataName:               "oauth-openshift",
			assertOperatorStatusApplyCalls: true,
			wantOperatorStatusApplyCalls:   0,
			wantSyncError:                  true,
			wantOperationError:             availabilityError,
		},
		{
			name:                           "reports and retries authentication status update failure",
			oidcAvailable:                  true,
			authentication:                 authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			statusUpdateError:              statusUpdateError,
			wantMetadataName:               "oauth-openshift",
			wantStatusUpdate:               true,
			wantAuthConfigCalls:            1,
			assertStatusUpdateLogsDisabled: true,
			wantSyncError:                  true,
			wantOperationError:             statusUpdateError,
			wantDegradedReason:             "UpdateStatusFailed",
		},
		{
			name:                "preserves both operand and condition apply failures",
			oidcAvailable:       true,
			authentication:      authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			operandPresent:      true,
			deleteError:         deleteError,
			operatorStatusError: conditionApplyError,
			wantMetadataName:    "oauth-openshift",
			wantDeleteAttempt:   true,
			wantSyncError:       true,
			wantOperationError:  deleteError,
			wantConditionError:  conditionApplyError,
		},
		{
			name:             "sets integrated OAuth metadata when OIDC is unavailable",
			authentication:   authentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			route:            route,
			wantMetadataName: "oauth-openshift",
			wantStatusUpdate: true,
		},
		{
			name:               "restores metadata from live status when the informer is stale",
			authentication:     authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			liveAuthentication: authentication(configv1.AuthenticationTypeOIDC, ""),
			route:              route,
			wantMetadataName:   "oauth-openshift",
			wantStatusUpdate:   true,
		},
		{
			name:             "retains OIDC metadata while OIDC is unavailable",
			authentication:   authentication(configv1.AuthenticationTypeOIDC, "oauth-openshift"),
			route:            route,
			wantMetadataName: "oauth-openshift",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			originalMetadataName := test.authentication.Status.IntegratedOAuthMetadata.Name
			liveAuthentication := test.liveAuthentication
			if liveAuthentication == nil {
				liveAuthentication = test.authentication.DeepCopy()
			}
			configClient := configfake.NewClientset(liveAuthentication)
			authenticationClient := &recordingAuthenticationClient{
				AuthenticationInterface: configClient.ConfigV1().Authentications(),
			}
			if test.statusUpdateError != nil {
				configClient.PrependReactor("update", "authentications", func(action clienttesting.Action) (bool, runtime.Object, error) {
					if action.GetSubresource() == "status" {
						return true, nil, test.statusUpdateError
					}
					return false, nil, nil
				})
			}

			var kubeObjects []runtime.Object
			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if test.operandPresent {
				operand := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "v4-0-config-system-metadata", Namespace: "openshift-authentication"},
				}
				if test.pendingDeletion {
					deletionTimestamp := metav1.NewTime(time.Now())
					operand.DeletionTimestamp = &deletionTimestamp
					operand.Finalizers = []string{"test-finalizer"}
				}
				if err := configMapIndexer.Add(operand); err != nil {
					t.Fatalf("failed to seed config map lister: %v", err)
				}
				kubeObjects = append(kubeObjects, operand)
			}
			kubeClient := k8sfake.NewClientset(kubeObjects...)
			if test.pendingDeletion {
				kubeClient.PrependReactor("delete", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, nil
				})
			} else if test.deleteError != nil {
				kubeClient.PrependReactor("delete", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.deleteError
				})
			}
			if test.configMapGetError != nil {
				kubeClient.PrependReactor("get", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.configMapGetError
				})
			}

			operatorStateClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
				&operatorv1.OperatorStatus{},
				nil,
			)
			operatorClient := &recordingOperatorClient{OperatorClient: operatorStateClient, applyError: test.operatorStatusError}
			fakeAuthConfigChecker := &fakeAuthenticationConfigChecker{
				oidcAvailable:   test.oidcAvailable,
				oidcError:       test.oidcError,
				authConfig:      test.authentication,
				authConfigError: test.authConfigError,
			}
			controller := &metadataController{
				controllerInstanceName: "test-metadata",
				configMapLister:        corev1listers.NewConfigMapLister(configMapIndexer),
				configMaps:             kubeClient.CoreV1(),
				route:                  staticRouteClient{route: test.route},
				authentication:         authenticationClient,
				operatorClient:         operatorClient,
				authConfigChecker:      fakeAuthConfigChecker,
			}

			recorder := events.NewInMemoryRecorder("metadata-controller-test", clocktesting.NewFakePassiveClock(time.Now()))
			syncContext := factory.NewSyncContext("metadata-controller-test", recorder)
			syncErr := controller.sync(ctx, syncContext)
			if (syncErr != nil) != test.wantSyncError {
				t.Fatalf("sync error = %v, want error %v", syncErr, test.wantSyncError)
			}
			if got := fakeAuthConfigChecker.authConfigCalls; got != test.wantAuthConfigCalls {
				t.Errorf("AuthConfig calls = %d, want %d", got, test.wantAuthConfigCalls)
			}
			if test.assertOperatorStatusApplyCalls && operatorClient.applyCalls != test.wantOperatorStatusApplyCalls {
				t.Errorf("operator status apply calls = %d, want %d", operatorClient.applyCalls, test.wantOperatorStatusApplyCalls)
			}
			if test.assertStatusUpdateLogsDisabled {
				if authenticationClient.statusUpdateContext == nil {
					t.Error("status update context was not captured")
				} else if klog.FromContext(authenticationClient.statusUpdateContext).V(8).Enabled() {
					t.Error("status update context enables client-go request and response body logging")
				}
			}
			if test.wantSyncError && !stderrors.Is(syncErr, test.wantOperationError) {
				t.Errorf("sync error = %v, want wrapped operation error %v", syncErr, test.wantOperationError)
			}
			if test.wantConditionError != nil && !stderrors.Is(syncErr, test.wantConditionError) {
				t.Errorf("sync error = %v, want condition apply error %v", syncErr, test.wantConditionError)
			}

			updatedAuthentication, err := configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to get authentication config after sync: %v", err)
			}
			if got := updatedAuthentication.Status.IntegratedOAuthMetadata.Name; got != test.wantMetadataName {
				t.Errorf("integratedOAuthMetadata.name = %q, want %q", got, test.wantMetadataName)
			}
			if got := test.authentication.Status.IntegratedOAuthMetadata.Name; got != originalMetadataName {
				t.Errorf("cached authentication metadata name = %q, want unchanged value %q", got, originalMetadataName)
			}

			if got := countAction(kubeClient.Actions(), "delete", "configmaps", ""); (got > 0) != test.wantDeleteAttempt {
				t.Errorf("config map delete attempted = %v, want %v", got > 0, test.wantDeleteAttempt)
			}
			if got := countAction(configClient.Actions(), "update", "authentications", "status"); (got > 0) != test.wantStatusUpdate {
				t.Errorf("authentication status updated = %v, want %v", got > 0, test.wantStatusUpdate)
			}

			_, operatorStatus, _, err := operatorStateClient.GetOperatorState()
			if err != nil {
				t.Fatalf("failed to get operator status: %v", err)
			}
			condition := v1helpers.FindOperatorCondition(operatorStatus.Conditions, "AuthConfigDegraded")
			if test.wantDegradedReason == "" {
				if condition != nil && condition.Status == operatorv1.ConditionTrue {
					t.Errorf("unexpected AuthConfigDegraded condition: %#v", condition)
				}
			} else if condition == nil || condition.Status != operatorv1.ConditionTrue || condition.Reason != test.wantDegradedReason {
				t.Errorf("AuthConfigDegraded condition = %#v, want True with reason %q", condition, test.wantDegradedReason)
			}

			if test.operandPresent && test.deleteError == nil && test.configMapGetError == nil {
				_, err := kubeClient.CoreV1().ConfigMaps("openshift-authentication").Get(ctx, "v4-0-config-system-metadata", metav1.GetOptions{})
				if test.pendingDeletion {
					if err != nil {
						t.Errorf("pending OAuth metadata ConfigMap should remain until finalizers complete, get error = %v", err)
					}
				} else if !apierrors.IsNotFound(err) {
					t.Errorf("OAuth metadata config map should be deleted, get error = %v", err)
				}
			}
		})
	}
}

func countAction(actions []clienttesting.Action, verb, resource, subresource string) int {
	count := 0
	for _, action := range actions {
		if action.Matches(verb, resource) && action.GetSubresource() == subresource {
			count++
		}
	}
	return count
}
