#!/usr/bin/env bash

set -o nounset
set -o pipefail
set -x

# Install multi-operator-manager. This will make sure the latest binary is installed
# If the installation failed, keep going, maybe the binary is available in the system
echo "Installing latest version of multi-operator-manager..."
if ! go install -mod=readonly github.com/openshift/multi-operator-manager/cmd/multi-operator-manager@latest; then
    echo "Error: Failed to install multi-operator-manager."
fi

# Check if the multi-operator-manager is installed; if not, fail
if ! command -v multi-operator-manager &> /dev/null; then
    echo "Error: multi-operator-manager binary not available."
    exit 1
fi

# Define the path to the operator binary
MOM_CMD="${MOM_CMD:-multi-operator-manager}"

# Define input and output directories (can be overridden if necessary)
APPLY_CONFIG_INPUT_DIR="${APPLY_CONFIG_INPUT_DIR:-./test-data/apply-configuration}"
APPLY_CONFIG_OUTPUT_DIR="${ARTIFACT_DIR:-./test-output}"

# Make sure the output-dir is clean
if [ -d "${APPLY_CONFIG_OUTPUT_DIR}" ]; then
    echo "Cleaning up existing ${APPLY_CONFIG_OUTPUT_DIR}"
    rm -rf "${APPLY_CONFIG_OUTPUT_DIR}"
fi

# Assemble the args
APPLY_CONFIG_ARGS=(
  test
  apply-configuration
  --test-dir="$APPLY_CONFIG_INPUT_DIR"
  --output-dir="$APPLY_CONFIG_OUTPUT_DIR"
)

# Run the apply-configuration command from the operator
if ! "${MOM_CMD}" "${APPLY_CONFIG_ARGS[@]}"; then
    # If the command fails, create an archive for easy downloading
    TMP_DIR="$(mktemp -d)"
    ARCHIVE_PATH="${TMP_DIR}/archive.tar.gz"
    tar -czf "${ARCHIVE_PATH}" -C "${APPLY_CONFIG_OUTPUT_DIR}" .
    mv "${ARCHIVE_PATH}" "${APPLY_CONFIG_OUTPUT_DIR}"
    rmdir "${TMP_DIR}"
    exit 1
fi
