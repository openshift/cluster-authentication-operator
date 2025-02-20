package render

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openshift/cluster-authentication-operator/bindata"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	FileModeDirectoryDefault os.FileMode = 0755
	FileModeFileDefault      os.FileMode = 0644
)

type RenderOptions struct {
	AssetOutputDir      string
	RenderedManifestDir string
	ClusterProfile      string
	PayloadVersion      string
	Assets              resourceapply.AssetFunc
	AssetsToRender      []string
}

func (ro *RenderOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&ro.AssetOutputDir, "asset-output-dir", ro.AssetOutputDir, "Output path for rendered manifests.")

	// Note: Currently these values are unused, but exist to support potential future addition of
	// feature-gate aware renderer functionality. Not providing these input-based flags from the beginning
	// and adding them later may break users using older versions of the openshift installer to install.
	// newer versions of openshift clusters. While we don't technically support this, including the input-based flags
	// now reduces our support burden in these cases.
	fs.StringVar(&ro.RenderedManifestDir, "rendered-manifest-dir", ro.RenderedManifestDir, "directory containing yaml or json manifests that will be created via cluster-bootstrapping")
	fs.StringVar(&ro.ClusterProfile, "cluster-profile", ro.ClusterProfile, "self-managed-high-availability, single-node-developer, ibm-cloud-managed")
	fs.StringVar(&ro.PayloadVersion, "payload-version", ro.PayloadVersion, "Version that will eventually be placed into ClusterOperator.status.  This normally comes from the CVO set via env var: OPERATOR_IMAGE_VERSION.")
}

func (ro *RenderOptions) Run() error {
	err := os.MkdirAll(ro.AssetOutputDir, FileModeDirectoryDefault)
	if err != nil {
		return fmt.Errorf("creating asset-output-dir: %w", err)
	}

	for _, assetToRender := range ro.AssetsToRender {
		asset, err := ro.Assets(assetToRender)
		if err != nil {
			return fmt.Errorf("getting asset %q to be rendered: %w", assetToRender, err)
		}

		filename := filepath.Join(ro.AssetOutputDir, filepath.Base(assetToRender))
		err = os.WriteFile(filename, asset, FileModeFileDefault)
		if err != nil {
			return fmt.Errorf("rendering asset %q to file %q: %w ", assetToRender, filename, err)
		}
	}

	return nil
}

// NewRender returns a cobra command responsible
// for rendering bootstrap manifests required by the
// cluster-authentication-operator
func NewRender() *cobra.Command {
	renderOpts := &RenderOptions{
		Assets: bindata.Asset,
		AssetsToRender: []string{
			"oauth-openshift/authorization.openshift.io_rolebindingrestrictions.yaml",
		},
	}

	renderCmd := &cobra.Command{
		Use:   "render",
		Short: "render bootstrap manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderOpts.Run()
		},
	}

	renderOpts.AddFlags(renderCmd.Flags())

	return renderCmd
}
