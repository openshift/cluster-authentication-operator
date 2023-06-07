all: build
.PHONY: all

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/deps-gomod.mk \
	targets/openshift/images.mk \
	targets/openshift/bindata.mk \
	targets/openshift/operator/telepresence.mk \
)

# Run core verification and all self contained tests.
#
# Example:
#   make check
check: | verify test-unit
.PHONY: check

IMAGE_REGISTRY?=registry.svc.ci.openshift.org

ENCRYPTION_PROVIDERS=aescbc aesgcm
ENCRYPTION_PROVIDER?=aescbc

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context directory for image build
# It will generate target "image-$(1)" for building the image and binding it as a prerequisite to target "images".
$(call build-image,ocp-cluster-authentication-operator,$(IMAGE_REGISTRY)/ocp/4.3:cluster-authentication-operator,./Dockerfile.rhel7,.)

# generate bindata targets
$(call add-bindata,assets,./bindata/...,bindata,assets,pkg/operator/assets/bindata.go)

$(call verify-golang-versions,Dockerfile.rhel7)

clean:
	$(RM) ./authentication-operator
.PHONY: clean

GO_TEST_PACKAGES :=./pkg/... ./cmd/...

# Run e2e tests.
#
# Example:
#   make test-e2e
test-e2e: GO_TEST_PACKAGES :=./test/e2e/...
test-e2e: GO_TEST_FLAGS += -v
test-e2e: GO_TEST_FLAGS += -timeout 1h
test-e2e: GO_TEST_FLAGS += -count 1
test-e2e: test-unit
.PHONY: test-e2e

run-e2e-test: GO_TEST_PACKAGES :=./test/e2e/...
run-e2e-test: GO_TEST_FLAGS += -timeout 1h
run-e2e-test: GO_TEST_FLAGS += -run
run-e2e-test: GO_TEST_FLAGS += ^${WHAT}$$
run-e2e-test: GO_TEST_PACKAGES += -count 1
run-e2e-test: test-unit
.PHONY: run-e2e-test

TEST_E2E_ENCRYPTION_TARGETS=$(addprefix test-e2e-encryption-,$(ENCRYPTION_PROVIDERS))

# these are extremely slow serial e2e encryption tests that modify the cluster's global state
test-e2e-encryption: GO_TEST_PACKAGES :=./test/e2e-encryption/...
test-e2e-encryption: GO_TEST_FLAGS += -v
test-e2e-encryption: GO_TEST_FLAGS += -timeout 4h
test-e2e-encryption: GO_TEST_FLAGS += -p 1
test-e2e-encryption: GO_TEST_ARGS += -args -provider=$(ENCRYPTION_PROVIDER)
test-e2e-encryption: test-unit
.PHONY: test-e2e-encryption

.PHONY: $(TEST_E2E_ENCRYPTION_TARGETS)
$(TEST_E2E_ENCRYPTION_TARGETS): test-e2e-encryption-%:
	ENCRYPTION_PROVIDER=$* $(MAKE) test-e2e-encryption

TEST_E2E_ENCRYPTION_PERF_TARGETS=$(addprefix test-e2e-encryption-perf-,$(ENCRYPTION_PROVIDERS))

test-e2e-encryption-perf: GO_TEST_PACKAGES :=./test/e2e-encryption-perf/...
test-e2e-encryption-perf: GO_TEST_FLAGS += -v
test-e2e-encryption-perf: GO_TEST_FLAGS += -timeout 2h
test-e2e-encryption-perf: GO_TEST_FLAGS += -p 1
test-e2e-encryption-perf: GO_TEST_ARGS += -args -provider=$(ENCRYPTION_PROVIDER)
test-e2e-encryption-perf: test-unit
.PHONY: test-e2e-encryption-perf

.PHONY: $(TEST_E2E_ENCRYPTION_PERF_TARGETS)
$(TEST_E2E_ENCRYPTION_PERF_TARGETS): test-e2e-encryption-perf-%:
	ENCRYPTION_PROVIDER=$* $(MAKE) test-e2e-encryption-perf

TEST_E2E_ENCRYPTION_ROTATION_TARGETS=$(addprefix test-e2e-encryption-rotation-,$(ENCRYPTION_PROVIDERS))

test-e2e-encryption-rotation: GO_TEST_PACKAGES :=./test/e2e-encryption-rotation/...
test-e2e-encryption-rotation: GO_TEST_FLAGS += -v
test-e2e-encryption-rotation: GO_TEST_FLAGS += -timeout 4h
test-e2e-encryption-rotation: GO_TEST_FLAGS += -p 1
test-e2e-encryption-rotation: GO_TEST_ARGS += -args -provider=$(ENCRYPTION_PROVIDER)
test-e2e-encryption-rotation: test-unit
.PHONY: test-e2e-encryption-rotation

.PHONY: $(TEST_E2E_ENCRYPTION_ROTATION_TARGETS)
$(TEST_E2E_ENCRYPTION_ROTATION_TARGETS): test-e2e-encryption-rotation-%:
	ENCRYPTION_PROVIDER=$* $(MAKE) test-e2e-encryption-rotation

# Configure the 'telepresence' target
# See vendor/github.com/openshift/build-machinery-go/scripts/run-telepresence.sh for usage and configuration details
export TP_DEPLOYMENT_YAML ?=./manifests/07_deployment.yaml
export TP_CMD_PATH ?=./cmd/authentication-operator
export TP_CMD_ARGS ?=operator --config=/var/run/configmaps/config/operator-config.yaml --v=2 --terminate-on-files=/var/run/configmaps/trusted-ca-bundle/ca-bundle.crt
export TP_LOCK_CONFIGMAP ?=cluster-authentication-operator-lock
export TP_BUILD_FLAGS ?=-tags ocp
