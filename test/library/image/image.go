package image

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// GetMappedImages returns the images if they were mapped to the provided
// image repository. The keys of the returned map are the same as the keys
// in originalImages and the values are the equivalent name in the target
// repo.
//
// This is basically a copy of github.com/openshift/origin/test/extended/util/image/image.go
func GetMappedImages(originalImages map[string]int, repo string) map[string]string {
	if len(repo) == 0 {
		images := make(map[string]string)
		for k := range originalImages {
			images[k] = k
		}
		return images
	}
	configs := make(map[string]string)
	reCharSafe := regexp.MustCompile(`[^\w]`)
	reDashes := regexp.MustCompile(`-+`)
	h := sha256.New()

	const (
		// length of hash in base64-url chosen to minimize possible collisions (64^16 possible)
		hashLength = 16
		// maximum length of a Docker spec image tag
		maxTagLength = 127
		// when building a tag, there are at most 6 characters in the format (e2e and 3 dashes),
		// and we should allow up to 10 digits for the index and additional qualifiers we may add
		// in the future
		tagFormatCharacters = 6 + 10
	)

	parts := strings.SplitN(repo, "/", 2)
	registry, destination := parts[0], parts[1]
	for pullSpec, index := range originalImages {
		// Build a new tag with the index, a hash of the image spec (to be unique) and
		// shorten and make the pull spec "safe" so it will fit in the tag
		h.Reset()
		h.Write([]byte(pullSpec))
		hash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:hashLength]
		shortName := reCharSafe.ReplaceAllLiteralString(pullSpec, "-")
		shortName = reDashes.ReplaceAllLiteralString(shortName, "-")
		maxLength := maxTagLength - hashLength - tagFormatCharacters
		if len(shortName) > maxLength {
			shortName = shortName[len(shortName)-maxLength:]
		}
		var newTag string
		if index == -1 {
			newTag = fmt.Sprintf("e2e-%s-%s", shortName, hash)
		} else {
			newTag = fmt.Sprintf("e2e-%d-%s-%s", index, shortName, hash)
		}

		configs[pullSpec] = fmt.Sprintf("%s/%s:%s", registry, destination, newTag)
	}
	return configs
}
