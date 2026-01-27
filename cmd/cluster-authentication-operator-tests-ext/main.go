package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"

	otecmd "github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	oteextension "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	oteginkgo "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift/cluster-authentication-operator/pkg/version"

	_ "github.com/openshift/cluster-authentication-operator/test/e2e"

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
	// Tests tagged with [Serial] and any of [Operator], [OIDC], [Templates], [Tokens] are included in this suite.
	extension.AddSuite(oteextension.Suite{
		Name:        "openshift/cluster-authentication-operator/operator/serial",
		Parallelism: 1,
		Qualifiers: []string{
			`name.contains("[Serial]") && (name.contains("[Operator]") || name.contains("[OIDC]") || name.contains("[Templates]") || name.contains("[Tokens]"))`,
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
