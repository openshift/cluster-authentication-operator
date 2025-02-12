package certrotationcontroller

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type OperatorConditionStatusReporter struct {
	// Plumbing:
	OperatorClient v1helpers.OperatorClient
}

func (s *OperatorConditionStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (bool, error) {
	newCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf(condition.CertRotationDegradedConditionTypeFmt, controllerName),
		Status: operatorv1.ConditionFalse,
	}
	if syncErr != nil {
		newCondition.Status = operatorv1.ConditionTrue
		newCondition.Reason = "CertificateRotationError"
		newCondition.Message = syncErr.Error()
	}
	_, updated, updateErr := v1helpers.UpdateStatus(ctx, s.OperatorClient, v1helpers.UpdateConditionFn(newCondition))
	return updated, updateErr
}

type CertRotationController struct {
	certRotators []factory.Controller
}

func NewCertRotationController(
	secretsGetter corev1client.SecretsGetter,
	configMapsGetter corev1client.ConfigMapsGetter,
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
	day time.Duration,
) (*CertRotationController, error) {
	ret := &CertRotationController{}

	targetNS := "openshift-oauth-apiserver"

	certRotator := certrotation.NewCertRotationController(
		"OAuthLoopbackCert",
		certrotation.RotatedSigningCASecret{
			Namespace: targetNS,
			Name:      "loopback-signer",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "oauth-apiserver",
			},
			Validity:               60 * day,
			Refresh:                30 * day,
			RefreshOnlyWhenExpired: false,
			Informer:               kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().Secrets(),
			Lister:                 kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().Secrets().Lister(),
			Client:                 secretsGetter,
			EventRecorder:          eventRecorder,
		},
		certrotation.CABundleConfigMap{
			Namespace: targetNS,
			Name:      "loopback-ca",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "oauth-apiserver",
			},
			Informer:      kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().ConfigMaps(),
			Lister:        kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().ConfigMaps().Lister(),
			Client:        configMapsGetter,
			EventRecorder: eventRecorder,
		},
		certrotation.RotatedSelfSignedCertKeySecret{
			Namespace: targetNS,
			Name:      "loopback",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "oauth-apiserver",
			},
			Validity:               30 * day,
			Refresh:                15 * day,
			RefreshOnlyWhenExpired: false,
			CertCreator: &certrotation.ServingRotation{
				Hostnames: func() []string { return []string{"apiserver-loopback-client"} },
			},
			Informer:      kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().Secrets(),
			Lister:        kubeInformersForNamespaces.InformersFor(targetNS).Core().V1().Secrets().Lister(),
			Client:        secretsGetter,
			EventRecorder: eventRecorder,
		},
		eventRecorder,
		&OperatorConditionStatusReporter{OperatorClient: operatorClient},
	)

	ret.certRotators = append(ret.certRotators, certRotator)

	return ret, nil
}

func (c *CertRotationController) Run(ctx context.Context, workers int) {
	syncCtx := context.WithValue(ctx, certrotation.RunOnceContextKey, false)
	for _, certRotator := range c.certRotators {
		go certRotator.Run(syncCtx, workers)
	}
}
