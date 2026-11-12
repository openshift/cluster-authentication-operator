package deployment

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

type hashInputSnapshot struct {
	values map[string]string
	hash   string
}

type hashInputObservation struct {
	baseline     bool
	inputs       []string
	added        []string
	removed      []string
	changed      []string
	previousHash string
	hashChanged  bool
}

// hashResourceVersions preserves the rollout hash's sorted, comma-separated encoding.
func hashResourceVersions(resourceVersions []string) string {
	sort.Strings(resourceVersions)
	hash := sha512.Sum512([]byte(strings.Join(resourceVersions, ",")))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// observeHashInputs compares consecutive calculations, including calculations whose
// Deployment is never applied. Only input strings are retained, never resource data.
func observeHashInputs(previous *hashInputSnapshot, proxy common.ResolvedProxy, configResourceVersions []string, hash string) (hashInputObservation, *hashInputSnapshot) {
	current := &hashInputSnapshot{
		values: map[string]string{
			"proxy.HTTPProxy":  proxy.HTTPProxy,
			"proxy.HTTPSProxy": proxy.HTTPSProxy,
			"proxy.NoProxy":    proxy.NoProxy,
		},
		hash: hash,
	}
	observation := hashInputObservation{
		baseline: previous == nil,
		inputs:   append([]string(nil), configResourceVersions...),
	}
	observation.inputs = append(observation.inputs, fmt.Sprintf("proxy:%s:%s:%s",
		redactProxyURL(proxy.HTTPProxy), redactProxyURL(proxy.HTTPSProxy), proxy.NoProxy))
	sort.Strings(observation.inputs)
	for _, input := range configResourceVersions {
		// The producer always emits kind:name:resourceVersion. Resource names
		// cannot contain colons; resourceVersions are the final component.
		key, value, _ := strings.Cut(input, ":")
		name, resourceVersion, _ := strings.Cut(value, ":")
		current.values[key+":"+name] = resourceVersion
	}
	if previous == nil {
		return observation, current
	}

	observation.previousHash = previous.hash
	observation.hashChanged = previous.hash != current.hash
	for key, value := range current.values {
		oldValue, found := previous.values[key]
		if !found {
			observation.added = append(observation.added, formatHashInput(key, value))
		} else if oldValue != value {
			observation.changed = append(observation.changed, fmt.Sprintf("%s: %q -> %q", key,
				redactHashInput(key, oldValue), redactHashInput(key, value)))
		}
	}
	for key, value := range previous.values {
		if _, found := current.values[key]; !found {
			observation.removed = append(observation.removed, formatHashInput(key, value))
		}
	}
	sort.Strings(observation.added)
	sort.Strings(observation.removed)
	sort.Strings(observation.changed)
	return observation, current
}

func formatHashInput(key, value string) string {
	return fmt.Sprintf("%s: %q", key, redactHashInput(key, value))
}

func redactHashInput(key, value string) string {
	if key == "proxy.HTTPProxy" || key == "proxy.HTTPSProxy" {
		return redactProxyURL(value)
	}
	return value
}

func redactProxyURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		// Parsing errors can include credentials; do not log the error or URL.
		return "<invalid proxy URL>"
	}
	if parsed.Opaque != "" && strings.Contains(value, "@") {
		return "<invalid proxy URL>"
	}
	if parsed.User != nil {
		parsed.User = url.User("REDACTED")
		return parsed.String()
	}
	return value
}
