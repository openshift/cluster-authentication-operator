package init

import (
	"os"

	"k8s.io/klog/v2"
)

func init() {
	// Configure klog to write to stderr as early as possible, before any test
	// package initialization that might generate klog output. This prevents
	// warnings from corrupting JSON output on stdout during test listing.
	klog.SetOutput(os.Stderr)
}
