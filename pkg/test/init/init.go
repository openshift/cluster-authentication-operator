package init

import (
	"flag"
	"io"

	"k8s.io/klog/v2"
)

func init() {
	// Completely suppress klog output during package initialization to prevent
	// any warnings (like feature gate warnings from k8s.io/apiserver) from
	// appearing before JSON test listing output.
	// This is critical because in CI environments, stderr may be combined with
	// stdout before JSON parsing, causing "invalid character 'W'" errors.
	klog.SetOutput(io.Discard)

	// Initialize klog's flags to prevent nil pointer panics
	// The flags may not be registered yet, so we need to do this carefully
	klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlags)

	// Set verbosity to 0 to suppress info/warning messages during init
	klogFlags.Set("v", "0")
	klogFlags.Set("logtostderr", "false")

	// After package initialization completes and the actual test command runs,
	// the OTE framework will reconfigure logging appropriately for test execution.
}
