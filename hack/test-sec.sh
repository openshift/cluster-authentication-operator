#!/bin/bash
source "$(dirname "${BASH_SOURCE}")/lib/init.sh"

os::util::ensure::gopath_binary_exists 'gosec' 'github.com/securego/gosec/cmd/gosec'

function cleanup() {
    return_code=$?
    os::util::describe_return_code "${return_code}"
    exit "${return_code}"
}
trap "cleanup" EXIT

gosec -severity medium --confidence medium -exclude G304 -quiet  ./...
