#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -x

# Check if the multi-operator-manager is installed; if not, install it
if ! command -v multi-operator-manager &> /dev/null; then
  echo "Installing multi-operator-manager..."
  if ! go install github.com/openshift/multi-operator-manager/cmd/multi-operator-manager@latest; then
    echo "Error: Failed to install multi-operator-manager."
    exit 1
  fi
fi

# Define the path to the operator binary (can be overridden if necessary)
MOM_CMD="${MOM_CMD:-multi-operator-manager}"

# Define input and output directories
APPLY_CONFIG_INPUT_DIR="${APPLY_CONFIG_INPUT_DIR:-./test-data/apply-configuration}"
APPLY_CONFIG_OUTPUT_DIR="${APPLY_CONFIG_OUTPUT_DIR:-./test-output}"

# Assemble the args
APPLY_CONFIG_ARGS=(
  test
  apply-configuration
  --test-dir="$APPLY_CONFIG_INPUT_DIR"
  --output-dir="$APPLY_CONFIG_OUTPUT_DIR"
)

# Run the apply-configuration command from the operator
"${MOM_CMD}" "${APPLY_CONFIG_ARGS[@]}"
