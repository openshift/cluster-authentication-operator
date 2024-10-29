package libraryinputresources

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sigs.k8s.io/yaml"
	"strings"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TODO this is a good target to move to library-go so we all agree how to reference these.
type Resource struct {
	Filename     string
	ResourceType schema.GroupVersionResource
	Content      *unstructured.Unstructured
}

func LenientResourcesFromDirRecursive(location string) ([]*Resource, error) {
	currResourceList := []*Resource{}
	errs := []error{}
	err := filepath.WalkDir(location, func(currLocation string, currFile fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
		}

		if currFile.IsDir() {
			return nil
		}
		if !strings.HasSuffix(currFile.Name(), ".yaml") && !strings.HasSuffix(currFile.Name(), ".json") {
			return nil
		}
		currResource, err := ResourceFromFile(currLocation, location)
		if err != nil {
			return fmt.Errorf("error deserializing %q: %w", currLocation, err)
		}
		currResourceList = append(currResourceList, currResource)

		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}

	return currResourceList, errors.Join(errs...)
}

func ResourceFromFile(location, fileTrimPrefix string) (*Resource, error) {
	content, err := os.ReadFile(location)
	if err != nil {
		return nil, fmt.Errorf("unable to read %q: %w", location, err)
	}

	ret, _, jsonErr := unstructured.UnstructuredJSONScheme.Decode(content, nil, &unstructured.Unstructured{})
	if jsonErr != nil {
		// try to see if it's yaml
		jsonString, err := yaml.YAMLToJSON(content)
		if err != nil {
			return nil, fmt.Errorf("unable to decode %q as json: %w", location, jsonErr)
		}
		ret, _, err = unstructured.UnstructuredJSONScheme.Decode(jsonString, nil, &unstructured.Unstructured{})
		if err != nil {
			return nil, fmt.Errorf("unable to decode %q as yaml: %w", location, err)
		}
	}

	retFilename := strings.TrimPrefix(location, fileTrimPrefix)
	retFilename = strings.TrimPrefix(retFilename, "/")

	return &Resource{
		Filename: retFilename,
		Content:  ret.(*unstructured.Unstructured),
	}, nil
}

func IdentifyResource(in *Resource) string {
	gvkString := fmt.Sprintf("%s.%s.%s/%s[%s]", in.Content.GroupVersionKind().Kind, in.Content.GroupVersionKind().Version, in.Content.GroupVersionKind().Group, in.Content.GetName(), in.Content.GetNamespace())

	return fmt.Sprintf("%s(%s)", gvkString, in.Filename)
}

func WriteResource(in *Resource, parentDir string) error {
	if len(in.Filename) == 0 {
		return fmt.Errorf("%s is missing filename", IdentifyResource(in))
	}

	dir := path.Join(parentDir, path.Dir(in.Filename))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating dir for %v: %w", IdentifyResource(in), err)
	}

	file := path.Join(parentDir, in.Filename)
	resourceYaml, err := yaml.Marshal(in.Content)
	if err != nil {
		return fmt.Errorf("error serializing %v: %w", IdentifyResource(in), err)
	}
	if err := os.WriteFile(file, resourceYaml, 0644); err != nil {
		return fmt.Errorf("error writing %v: %w", IdentifyResource(in), err)
	}

	return nil
}

func EquivalentResources(field string, lhses, rhses []*Resource) []string {
	reasons := []string{}

	for i := range lhses {
		lhs := lhses[i]
		rhs := findResource(rhses, lhs.Filename)

		if rhs == nil {
			reasons = append(reasons, fmt.Sprintf("%v[%d]: %q missing in rhs", field, i, lhs.Filename))
			continue
		}
		if !reflect.DeepEqual(lhs.Content, rhs.Content) {
			reasons = append(reasons, fmt.Sprintf("%v[%d]: does not match: %v", field, i, cmp.Diff(lhs.Content, rhs.Content)))
		}
	}

	for i := range rhses {
		rhs := rhses[i]
		lhs := findResource(lhses, rhs.Filename)

		if lhs == nil {
			reasons = append(reasons, fmt.Sprintf("%v[%d]: %q missing in lhs", field, i, rhs.Filename))
			continue
		}
	}

	return reasons
}

func findResource(in []*Resource, filename string) *Resource {
	for _, curr := range in {
		if curr.Filename == filename {
			return curr
		}
	}

	return nil
}
