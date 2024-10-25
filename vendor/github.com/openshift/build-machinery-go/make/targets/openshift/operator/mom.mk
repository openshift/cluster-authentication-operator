scripts_dir :=$(shell realpath $(dir $(lastword $(MAKEFILE_LIST)))../../../../scripts)

test-operator-integration: build
	bash $(scripts_dir)/test-operator-integration.sh
.PHONY: test-operator-integration

