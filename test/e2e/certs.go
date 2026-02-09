package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Operator][Certs] TestRouterCerts", func() {
		testRouterCerts(g.GinkgoTB())
	})
})

func testRouterCerts(t testing.TB) {
	clients := e2e.NewTestClients(t)

	// make sure cluster operator is settled before continuing
	err := e2e.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	require.NoError(t, err)

	// generate crypto materials
	rootCA := e2e.NewCertificateAuthorityCertificate(t, nil)
	intermediateCA := e2e.NewCertificateAuthorityCertificate(t, rootCA)
	server := e2e.NewServerCertificate(t, intermediateCA, "*.testing")

	// create tls secret
	var certificates bytes.Buffer
	certificates.Write(pem.EncodeToMemory(&pem.Block{Type: cert.CertificateBlockType, Bytes: server.Certificate.Raw}))
	certificates.Write(pem.EncodeToMemory(&pem.Block{Type: cert.CertificateBlockType, Bytes: intermediateCA.Certificate.Raw}))
	certificates.Write(pem.EncodeToMemory(&pem.Block{Type: cert.CertificateBlockType, Bytes: rootCA.Certificate.Raw}))
	privateKey, err := keyutil.MarshalPrivateKeyToPEM(server.PrivateKey)
	require.NoError(t, err)
	// Generate a valid Kubernetes name from the test name
	secretName := e2e.SanitizeResourceName(t.Name())

	secret, err := clients.KubeClient.CoreV1().Secrets("openshift-ingress").Create(
		context.TODO(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{GenerateName: secretName + "-"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certificates.Bytes(),
				"tls.key": privateKey,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer func() {
		_ = clients.KubeClient.CoreV1().Secrets(secret.Namespace).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})
	}()

	// set custom ingress defaultCertificate
	ingressController, err := clients.OperatorClient.OperatorV1().IngressControllers("openshift-ingress-operator").Get(context.TODO(), "default", metav1.GetOptions{})
	require.NoError(t, err)
	backup := ingressController.Spec.DefaultCertificate
	defer func() {
		ingressController, err := clients.OperatorClient.OperatorV1().IngressControllers("openshift-ingress-operator").Get(context.TODO(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		ingressController.Spec.DefaultCertificate = backup
		_, _ = clients.OperatorClient.OperatorV1().IngressControllers(ingressController.Namespace).Update(context.TODO(), ingressController, metav1.UpdateOptions{})
	}()
	ingressController.Spec.DefaultCertificate = &corev1.LocalObjectReference{Name: secret.Name}
	_, err = clients.OperatorClient.OperatorV1().IngressControllers(ingressController.Namespace).Update(context.TODO(), ingressController, metav1.UpdateOptions{})
	require.NoError(t, err)

	// wait for RouterCertsDegraded == true
	var condition *operatorv1.OperatorCondition
	err = wait.PollImmediate(time.Second, 10*time.Minute, func() (bool, error) {
		config, err := clients.OperatorClient.OperatorV1().Authentications().Get(context.TODO(), "cluster", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("Unable to retrieve operator config: %v", err)
			return false, nil
		}
		if err != nil {
			return false, err
		}
		conditions := config.Status.Conditions
		condition = v1helpers.FindOperatorCondition(conditions, "RouterCertsDegraded")
		return condition != nil && condition.Status == operatorv1.ConditionTrue, nil
	})
	require.NoError(t, err)
	require.NotNilf(t, condition, "unable to find the %v condition", "RouterCertsDegraded")
	require.Regexp(t, "InvalidServerCertRouterCerts", condition.Reason)
}
