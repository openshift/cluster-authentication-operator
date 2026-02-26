package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"

	otecmd "github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	oteextension "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	oteginkgo "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift/cluster-authentication-operator/pkg/version"

	_ "github.com/openshift/cluster-authentication-operator/test/e2e"
	_ "github.com/openshift/cluster-authentication-operator/test/e2e-encryption"
	// TODO: Uncomment when e2e-encryption-kms is migrated to Ginkgo format
	// _ "github.com/openshift/cluster-authentication-operator/test/e2e-encryption-kms"
	_ "github.com/openshift/cluster-authentication-operator/test/e2e-encryption-perf"
	_ "github.com/openshift/cluster-authentication-operator/test/e2e-encryption-rotation"
	_ "github.com/openshift/cluster-authentication-operator/test/e2e-oidc"

	"k8s.io/klog/v2"
)

func main() {
	cmd, err := newOperatorTestCommand()
	if err != nil {
		klog.Fatal(err)
	}
	code := cli.Run(cmd)
	os.Exit(code)
}

func newOperatorTestCommand() (*cobra.Command, error) {
	registry, err := prepareOperatorTestsRegistry()
	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:   "cluster-authentication-operator-tests-ext",
		Short: "A binary used to run cluster-authentication-operator tests as part of OTE.",
		Run: func(cmd *cobra.Command, args []string) {
			// no-op, logic is provided by the OTE framework
			if err := cmd.Help(); err != nil {
				klog.Fatal(err)
			}
		},
	}

	if v := version.Get().String(); len(v) == 0 {
		cmd.Version = "<unknown>"
	} else {
		cmd.Version = v
	}

	cmd.AddCommand(otecmd.DefaultExtensionCommands(registry)...)

	return cmd, nil
}

func prepareOperatorTestsRegistry() (*oteextension.Registry, error) {
	registry := oteextension.NewRegistry()
	extension := oteextension.NewExtension("openshift", "payload", "cluster-authentication-operator")

	// The following suite runs tests that verify the operator's behaviour.
	// This suite is executed only on pull requests targeting this repository.
	// Tests that are not tagged with [Serial] and have any of [Operator], [Templates], [Tokens] are included in this suite.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator/parallel",
		Parallelism: 4,
		Qualifiers: []string{
			`!name.contains("[Serial]") && (name.contains("[Operator]") || name.contains("[Templates]") || name.contains("[Tokens]"))`,
		},
	})

	// The following suite runs tests that must execute serially (one at a time)
	// because they modify cluster-wide resources like OAuth configuration.
	// Tests tagged with [Serial] and any of [Operator], [OIDC], [Templates], [Tokens] are included in this suite.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Serial]") && (name.contains("[Operator]") || name.contains("[OIDC]") || name.contains("[Templates]") || name.contains("[Tokens]"))`,
		},
	})

	// The following suite runs basic encryption tests that modify cluster-wide encryption configuration.
	// These tests must run serially as they configure encryption settings.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator-encryption/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Encryption]") && name.contains("[Serial]") && !name.contains("Rotation") && !name.contains("Perf") && !name.contains("KMS")`,
		},
	})

	// The following suite runs encryption rotation tests.
	// These tests must run serially as they configure encryption settings.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator-encryption-rotation/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Encryption]") && name.contains("[Serial]") && name.contains("Rotation")`,
		},
	})

	// The following suite runs encryption performance tests.
	// These tests must run serially as they configure encryption settings and measure performance.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator-encryption-perf/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Encryption]") && name.contains("[Serial]") && name.contains("Perf")`,
		},
	})

	// The following suite runs KMS encryption tests.
	// These tests must run serially as they configure KMS encryption settings.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator-encryption-kms/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Encryption]") && name.contains("[Serial]") && name.contains("KMS")`,
		},
	})

	// The following suite runs OIDC-specific disruptive tests.
	// These tests must run serially as they modify cluster authentication configuration
	// and may disrupt cluster operations.
	defaultTimeout := 120 * time.Minute
	extension.AddSuite(oteextension.Suite{
		Name:             "openshift/cluster-authentication-operator/oidc/serial-disruptive",
		Parallelism:      1,
		ClusterStability: oteextension.ClusterStabilityDisruptive,
		TestTimeout:      &defaultTimeout,
		Qualifiers: []string{
			`name.contains("[OIDC]") && name.contains("[Serial]") && name.contains("[Disruptive]")`,
		},
	})

	specs, err := oteginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		return nil, fmt.Errorf("couldn't build extension test specs from ginkgo: %w", err)
	}

	extension.AddSpecs(specs)
	registry.Register(extension)
	return registry, nil
}
