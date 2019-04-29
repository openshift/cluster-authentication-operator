package operator2

import (
	"testing"
)

func TestInValidManagedConsoleConfig(t *testing.T) {
	cm := getCliConfigMap([]byte(`
kind: Console
apiVersion: config.openshift.io/v1
customization:
  branding: okd
  documentationBaseURL: https://docs.okd.io/4.0/
`))
	_, err := managedConsoleConfigBytes(cm)
	if err != nil {
		t.Fatal("Error in embedded object", err)
	}
}

func TestValidManagedConsoleConfig(t *testing.T) {
	cm := getCliConfigMap([]byte(`
kind: FeatureGate
apiVersion: config.openshift.io/v1
`))
	_, err := managedConsoleConfigBytes(cm)
	if err == nil {
		t.Fatal("Only Console objects are allowed")
	}
}
