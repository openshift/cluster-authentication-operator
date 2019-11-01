package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	authopclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestDeploymentMissingReplicas(t *testing.T) {
	kubeConfig, err := test.NewClientConfigForTest()
	require.NoError(t, err)

	authOperatorClient := authopclient.NewForConfigOrDie(kubeConfig).Authentications()
	require.NoError(t, err)

	origOperator, err := authOperatorClient.Get("cluster", metav1.GetOptions{})
	require.NoError(t, err)

	defer func() {
		// get the operator to the original form
		currentOperator, err := authOperatorClient.Get("cluster", metav1.GetOptions{})
		require.NoError(t, err)

		origOperator.ResourceVersion = currentOperator.ResourceVersion
		_, err = authOperatorClient.Update(origOperator)
		require.NoError(t, err)
	}()

	operator := origOperator.DeepCopy()

	osinv1Scheme := runtime.NewScheme()
	utilruntime.Must(configv1.Install(osinv1Scheme))
	utilruntime.Must(osinv1.Install(osinv1Scheme))
	osinv1Codec := serializer.NewCodecFactory(osinv1Scheme).LegacyCodec(osinv1.GroupVersion)

	operator.Spec.UnsupportedConfigOverrides = runtime.RawExtension{
		Raw: []byte(
			runtime.EncodeOrDie(
				osinv1Codec,
				runtime.Object(&osinv1.OsinServerConfig{
					GenericAPIServerConfig: configv1.GenericAPIServerConfig{
						ServingInfo: configv1.HTTPServingInfo{ServingInfo: configv1.ServingInfo{CertInfo: configv1.CertInfo{CertFile: "breaking_stuff"}}},
					},
				}),
			),
		),
	}

	_, err = authOperatorClient.Update(operator)
	require.NoError(t, err, "unable to update the operator")

	expectedCondition := &operatorv1.OperatorCondition{
		Type:    "Progressing",
		Status:  operatorv1.ConditionTrue,
		Reason:  "OAuthServerDeploymentNotReady",
		Message: "not all deployment replicas are ready",
	}

	err = WaitForOperatorCondition(t, authOperatorClient, expectedCondition)
	require.NoError(t, err, "the operator status never contained the conditions: %#v", expectedCondition)
}

func WaitForOperatorCondition(t *testing.T, client authopclient.AuthenticationInterface, expectedCondition *operatorv1.OperatorCondition) error {
	return wait.PollImmediate(time.Second, 5*time.Minute, func() (bool, error) {
		operator, err := client.Get("cluster", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("Unable to retrieve authentication operator: %v", err)
			return false, nil
		}
		if err != nil {
			return false, err
		}

		actualCondition := v1helpers.FindOperatorCondition(operator.Status.Conditions, expectedCondition.Type)
		return compareConditions(expectedCondition, actualCondition), nil
	})
}

func compareConditions(c1, c2 *operatorv1.OperatorCondition) bool {
	if c1 == c2 { // both are nil or the same pointer
		return true
	} else if c1 == nil || c2 == nil { // different pointer, one might be nil
		return false
	}

	return c1.Type == c2.Type && c1.Status == c2.Status &&
		c1.Reason == c2.Reason && c1.Message == c2.Message
}
