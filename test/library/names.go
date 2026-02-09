package library

import (
	"regexp"
	"strings"
)

// SanitizeResourceName converts a test name into a valid Kubernetes resource name
// compliant with RFC 1123 subdomain rules: lowercase alphanumeric characters, '-' or '.',
// starting and ending with an alphanumeric character. The maximum length is 63 characters.
func SanitizeResourceName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Split by dots to process each label separately (RFC 1123 requires each label
	// between dots to start and end with alphanumeric characters)
	labels := strings.Split(name, ".")
	validLabels := make([]string, 0, len(labels))

	invalidChars := regexp.MustCompile(`[^a-z0-9\-]+`)
	consecutiveHyphens := regexp.MustCompile(`-+`)

	for _, label := range labels {
		// Replace invalid characters with hyphens
		label = invalidChars.ReplaceAllString(label, "-")
		// Replace consecutive hyphens with a single hyphen
		label = consecutiveHyphens.ReplaceAllString(label, "-")
		// Remove leading/trailing hyphens from this label
		label = strings.Trim(label, "-")
		// Only include non-empty labels
		if label != "" {
			validLabels = append(validLabels, label)
		}
	}

	// Rejoin labels with dots
	name = strings.Join(validLabels, ".")

	// Kubernetes resource names have a maximum length of 63 characters
	if len(name) > 63 {
		name = name[:63]
	}
	// Ensure it doesn't end with a hyphen or dot after truncation
	name = strings.TrimRight(name, "-.")
	return name
}
