package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"
)

func main() {
	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cluster-authentication-operator")

	timeout := 120 * time.Minute
	// Should only ever be run by itself
	ext.AddSuite(e.Suite{
		Name: "cluster-authentication-operator/externaloidc/configure",
		Qualifiers: []string{
			`name.contains("[Suite: cluster-authentication-operator/externaloidc/configure") && !name.contains("[Skipped]")`,
		},
		ClusterStability: e.ClusterStabilityDisruptive,
		TestTimeout:      &timeout,
	})

	// Should only ever be run by itself
	ext.AddSuite(e.Suite{
		Name: "cluster-authentication-operator/externaloidc/revert",
		Qualifiers: []string{
			`name.contains("[Suite: cluster-authentication-operator/externaloidc/revert") && !name.contains("[Skipped]")`,
		},
		ClusterStability: e.ClusterStabilityDisruptive,
		TestTimeout:      &timeout,
	})

	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	configureSpecs := et.ExtensionTestSpecs{}
	revertSpecs := et.ExtensionTestSpecs{}
	specs.Walk(func(ets *et.ExtensionTestSpec) {
		if strings.Contains(ets.Name, "[Suite: cluster-authentication-operator/externaloidc/configure") {
			configureSpecs = append(configureSpecs, ets)
		}

		if strings.Contains(ets.Name, "[Suite: cluster-authentication-operator/externaloidc/revert") {
			revertSpecs = append(revertSpecs, ets)
		}
	})

	configureSpecs.AddBeforeAll(func() {
		// TODO: do common setup logic for configuration specs
	})

	revertSpecs.AddBeforeAll(func() {
		// TODO: do common setup logic for revert specs
	})

	ext.AddSpecs(configureSpecs)
	ext.AddSpecs(revertSpecs)
	registry.Register(ext)

	root := &cobra.Command{
		Long: "cluster-authentication-operator tests extension",
	}

	root.AddCommand(cmd.DefaultExtensionCommands(registry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}
