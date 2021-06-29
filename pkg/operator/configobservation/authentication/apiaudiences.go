package auth

import (
	"fmt"
	"net/url"
	"strings"

	"k8s.io/klog/v2"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
)

var (
	audiencesPath = []string{"apiServerArguments", "api-audiences"}
)

// ObserveAPIAudiences changes apiServerArguments.api-audiences from
// the default value if Authentication.Spec.ServiceAccountIssuer specifies a valid
// non-empty value.
func ObserveAPIAudiences(
	genericListers configobserver.Listers,
	recorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, errs []error) {
	defer func() {
		ret = configobserver.Pruned(ret, audiencesPath)
	}()

	listers := genericListers.(configobservation.Listers)
	errs = []error{}
	var issuerChanged bool
	var existingAudience, newAudience string
	// when the issuer will change, indicate that by setting `issuerChanged` to true
	// to emit the informative event
	defer func() {
		if !issuerChanged {
			return
		}

		recorder.Eventf(
			"ObserveAPIAudiences",
			"service account issuer changed from %s to %s",
			existingAudience, newAudience,
		)
	}()

	existingAudiences, _, err := unstructured.NestedStringSlice(existingConfig, audiencesPath...)
	if err != nil {
		errs = append(errs, fmt.Errorf("unable to extract service account issuer from unstructured: %v", err))
	}

	// we're using the value of authentication.spec.issuer which is always a string, not a slice
	if len(existingAudiences) > 0 {
		existingAudience = existingAudiences[0]
	}

	authConfig, err := listers.AuthConfigLister().Get("cluster")
	if apierrors.IsNotFound(err) {
		klog.Warningf("authentications.config.openshift.io/cluster: not found")
		// No issuer if the auth config is missing
		authConfig = &configv1.Authentication{}
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	newAudience = authConfig.Spec.ServiceAccountIssuer
	if len(newAudience) == 0 {
		newAudience = "https://kubernetes.default.svc"
	} else if err := checkIssuer(newAudience); err != nil {
		return existingConfig, append(errs, err)
	}

	// set `issuerChanged` to emit an event about config change in defer
	issuerChanged = existingAudience != newAudience

	return map[string]interface{}{
		"apiServerArguments": map[string]interface{}{
			"api-audiences": []interface{}{
				newAudience,
			},
		},
	}, errs
}

// checkIssuer validates the issuer in the same way that it will be validated by
// kube-apiserver
func checkIssuer(issuer string) error {
	if !strings.Contains(issuer, ":") {
		return nil
	}
	// If containing a colon, must parse without error as a url
	_, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("service-account issuer contained a ':' but was not a valid URL: %v", err)
	}
	return nil
}
