package render_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openshift/cluster-authentication-operator/pkg/cmd/render"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

func TestRenderOptionsRun(t *testing.T) {
	type testcase struct {
		name           string
		assets         resourceapply.AssetFunc
		assetsToRender []string
		expectedErr    error
		expectedAssets map[string][]byte
	}

	testcases := []testcase{
		{
			name: "asset-output-dir can be created, fetching asset fails, error",
			assets: func(name string) ([]byte, error) {
				return nil, errors.New("boom")
			},
			assetsToRender: []string{
				"foobar",
			},
			expectedAssets: make(map[string][]byte),
			expectedErr:    errors.New("getting asset \"foobar\" to be rendered:"),
		},
		{
			name: "asset-output-dir can be created, fetching asset successful, no error, manifest rendered successfully",
			assets: func(name string) ([]byte, error) {
				return []byte("baz"), nil
			},
			assetsToRender: []string{
				"foobar",
			},
			expectedAssets: map[string][]byte{
				"foobar": []byte("baz"),
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			renderOpts := &render.RenderOptions{
				AssetOutputDir: tempDir,
				Assets:         tc.assets,
				AssetsToRender: tc.assetsToRender,
			}
			err := renderOpts.Run()
			switch {
			case err != nil && tc.expectedErr != nil:
				if !strings.Contains(err.Error(), tc.expectedErr.Error()) {
					t.Fatalf("received error %q does not contain expected error substring %q", err.Error(), tc.expectedErr.Error())
				}
			case err != nil && tc.expectedErr == nil:
				t.Fatalf("received unexpected error %v", err)
			case err == nil && tc.expectedErr != nil:
				t.Fatalf("expected and error containing substring %q but did not receive an error", tc.expectedErr.Error())
			}

			for path, contents := range tc.expectedAssets {
				file, err := os.Open(filepath.Join(tempDir, path))
				if err != nil {
					if os.IsNotExist(err) {
						t.Fatalf("expected rendered manifest %q to exist in filesystem but it does not", path)
					}
					t.Fatalf("received unexpected error when checking for existence of rendered manifest %q in filesystem: %v", path, err)
				}

				fileContents, err := io.ReadAll(file)
				if err != nil {
					t.Fatalf("received unexpected error when reading contents of file %q: %v", path, err)
				}

				if !bytes.Equal(fileContents, contents) {
					t.Fatalf("contents for rendered manifest %q do not match the expected. Rendered contents: %v, expected: %v", path, string(fileContents), string(contents))
				}
			}
		})
	}
}
