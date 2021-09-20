package trustdistribution

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	configinformers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

type trustDistributionController struct {
	configMaps    corev1client.ConfigMapsGetter
	secretsLister corev1listers.SecretLister

	ingressLister configlistersv1.IngressLister
}

func NewTrustDistributionController(
	cmClient corev1client.ConfigMapsGetter,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	ingressInformer configinformers.IngressInformer,
	eventsRecorder events.Recorder,
) factory.Controller {
	c := &trustDistributionController{
		configMaps:    cmClient,
		secretsLister: kubeInformersForNamespaces.SecretLister(),
		ingressLister: ingressInformer.Lister(),
	}

	return factory.New().
		WithInformers(
			ingressInformer.Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-authentication").Core().V1().Secrets().Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		).
		WithSync(c.sync).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController("TrustDistributionController", eventsRecorder.WithComponentSuffix("trust-distribution"))
}

func (c *trustDistributionController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	ingressConfig, err := c.ingressLister.Get("cluster")
	if err != nil {
		return err
	}

	certBundle, _, _, err := common.GetActiveRouterCertKeyBytes(c.secretsLister,
		ingressConfig,
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"v4-0-config-system-custom-router-certs",
	)
	if err != nil {
		return err
	}

	var certsFiltered string
	var errs []error

	// filter the content for certificates only, the router-secret contains private keys
	// in the bundle as well
	for block, rest := pem.Decode(certBundle); block != nil; block, rest = pem.Decode(rest) {
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errs = append(errs, err)
		}

		certsFiltered += "\n" + string(pem.EncodeToMemory(block))
	}

	if len(certsFiltered) == 0 {
		return utilerrors.NewAggregate(errs)
	}

	_, _, err = resourceapply.ApplyConfigMap(ctx,
		c.configMaps,
		syncContext.Recorder(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "oauth-serving-cert",
				Namespace: "openshift-config-managed",
			},
			Data: map[string]string{
				"ca-bundle.crt": certsFiltered,
			},
		})

	return err
}
