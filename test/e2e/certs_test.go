package e2e

import (
	"bytes"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestRouterCerts(t *testing.T) {
	kubeConfig, err := e2e.NewClientConfigForTest()
	require.NoError(t, err)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)
	configClient, err := configclient.NewForConfig(kubeConfig)
	require.NoError(t, err)
	operatorClientset, err := operatorclient.NewForConfig(kubeConfig)
	require.NoError(t, err)
	// make sure cluster operator is settled before continuing
	err = e2e.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient.ConfigV1(), "authentication")
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
	secret, err := kubeClient.CoreV1().Secrets("openshift-ingress").Create(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{GenerateName: strings.ReplaceAll(strings.ToLower(t.Name()), "/", " ") + "-"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certificates.Bytes(),
				"tls.key": privateKey,
			},
		})
	require.NoError(t, err)
	defer func() {
		_ = kubeClient.CoreV1().Secrets(secret.Namespace).Delete(secret.Name, &metav1.DeleteOptions{})
	}()

	// set custom ingress defaultCertificate
	ingressController, err := operatorClientset.OperatorV1().IngressControllers("openshift-ingress-operator").Get("default", metav1.GetOptions{})
	require.NoError(t, err)
	backup := ingressController.Spec.DefaultCertificate
	defer func() {
		ingressController, err := operatorClientset.OperatorV1().IngressControllers("openshift-ingress-operator").Get("default", metav1.GetOptions{})
		require.NoError(t, err)
		ingressController.Spec.DefaultCertificate = backup
		_, _ = operatorClientset.OperatorV1().IngressControllers(ingressController.Namespace).Update(ingressController)
	}()
	ingressController.Spec.DefaultCertificate = &corev1.LocalObjectReference{Name: secret.Name}
	_, err = operatorClientset.OperatorV1().IngressControllers(ingressController.Namespace).Update(ingressController)
	require.NoError(t, err)

	// wait for RouterCertsDegraded == true
	var condition *operatorv1.OperatorCondition
	err = wait.PollImmediate(time.Second, 10*time.Minute, func() (bool, error) {
		config, err := operatorClientset.OperatorV1().Authentications().Get("cluster", metav1.GetOptions{})
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
