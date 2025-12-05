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
	"github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc"
	"github.com/spf13/cobra"

	_ "github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc/configure"
	_ "github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc/revert"
	_ "github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc/uidextra"
)

func main() {
	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cluster-authentication-operator")

	timeout := 120 * time.Minute

	// Should only ever be run by itself, so no parent
	ext.AddSuite(e.Suite{
		Name: "cluster-authentication-operator/externaloidc/configure",
		Qualifiers: []string{
			`name.contains("[Suite:cluster-authentication-operator/externaloidc/configure") && !name.contains("[Skipped]")`,
		},
		ClusterStability: e.ClusterStabilityDisruptive,
		TestTimeout:      &timeout,
		Parallelism:      1,
		RunConstraint:    e.RunConstraintWholeSuite,
	})

	// Should only ever be run by itself, so no parent
	ext.AddSuite(e.Suite{
		Name: "cluster-authentication-operator/externaloidc/revert",
		Qualifiers: []string{
			`name.contains("[Suite:cluster-authentication-operator/externaloidc/revert") && !name.contains("[Skipped]")`,
		},
		ClusterStability: e.ClusterStabilityDisruptive,
		TestTimeout:      &timeout,
		Parallelism:      1,
		RunConstraint:    e.RunConstraintWholeSuite,
	})

	// Should only ever be run by itself, so no parent
	ext.AddSuite(e.Suite{
		Name: "cluster-authentication-operator/externaloidc/uidextra",
		Qualifiers: []string{
			`name.contains("[Suite:cluster-authentication-operator/externaloidc/uidextra") && !name.contains("[Skipped]")`,
		},
		ClusterStability: e.ClusterStabilityDisruptive,
		TestTimeout:      &timeout,
		Parallelism:      1,
		RunConstraint:    e.RunConstraintWholeSuite,
	})

	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	configureSpecs := et.ExtensionTestSpecs{}
	revertSpecs := et.ExtensionTestSpecs{}
	uidExtraSpecs := et.ExtensionTestSpecs{}
	specs.Walk(func(ets *et.ExtensionTestSpec) {
		if strings.Contains(ets.Name, "[Suite:cluster-authentication-operator/externaloidc/configure") {
			configureSpecs = append(configureSpecs, ets)
		}

		if strings.Contains(ets.Name, "[Suite:cluster-authentication-operator/externaloidc/revert") {
			revertSpecs = append(revertSpecs, ets)
		}

		if strings.Contains(ets.Name, "[Suite:cluster-authentication-operator/externaloidc/uidextra") {
			uidExtraSpecs = append(uidExtraSpecs, ets)
		}
	})

	configureCommonizer := externaloidc.NewCommonizer(externaloidc.ConfigureSuiteBeforeAllExtra())
	configureSpecs.AddBeforeAll(func() {
		err := configureCommonizer.SuiteBeforeAll()
		if err != nil {
			panic(fmt.Sprintf("error in before all setup: %v", err))
		}
	})

	configureSpecs.AddAfterAll(func() {
		err := configureCommonizer.SuiteAfterAll()
		if err != nil {
			panic(fmt.Sprintf("error in after all: %v", err))
		}
	})

	revertCommonizer := externaloidc.NewCommonizer(externaloidc.RevertSuiteBeforeAllExtra())
	revertSpecs.AddBeforeAll(func() {
		err := revertCommonizer.SuiteBeforeAll()
		if err != nil {
			panic(fmt.Sprintf("error in before all: %v", err))
		}
	})

	revertSpecs.AddAfterAll(func() {
		err := revertCommonizer.SuiteAfterAll()
		if err != nil {
			panic(fmt.Sprintf("error in after all: %v", err))
		}
	})

	uidExtraCommonizer := externaloidc.NewCommonizer(externaloidc.UIDExtraSuiteBeforeAllExtra())
	uidExtraSpecs.AddBeforeAll(func() {
		err := uidExtraCommonizer.SuiteBeforeAll()
		if err != nil {
			panic(fmt.Sprintf("error in before all: %v", err))
		}
	})

	uidExtraSpecs.AddAfterAll(func() {
		err := uidExtraCommonizer.SuiteAfterAll()
		if err != nil {
			panic(fmt.Sprintf("error in after all: %v", err))
		}
	})

	ext.AddSpecs(configureSpecs)
	ext.AddSpecs(revertSpecs)
	ext.AddSpecs(uidExtraSpecs)

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
