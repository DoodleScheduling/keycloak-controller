
# Image URL to use all building/pushing image targets
PROXY_IMG ?= keycloak-controller-proxy:latest
IMG ?= keycloak-controller:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.27

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/base/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: tidy
tidy: ## Run go mod tidy
	go mod tidy

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint against code
	$(GOLANGCI_LINT) run --timeout=2m ./...

.PHONY: test
test: manifests generate fmt vet tidy envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -v -coverprofile coverage.out -race

##@ Build

.PHONY: build
build: generate fmt vet tidy ## Build manager binary.
	CGO_ENABLED=0 go build -o manager main.go
	CGO_ENABLED=0 go build -o proxy/proxy ./proxy/

.PHONY: run
run: manifests generate fmt vet tidy ## Run a controller from your host.
	go run ./main.go --log-level=debug

# Find or download gen-crd-api-reference-docs
GEN_CRD_API_REFERENCE_DOCS = $(GOBIN)/gen-crd-api-reference-docs
.PHONY: gen-crd-api-reference-docs
gen-crd-api-reference-docs:
	$(call go-install-tool,$(GEN_CRD_API_REFERENCE_DOCS),github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0)

# Generate API reference documentation
api-docs: gen-crd-api-reference-docs
	$(GEN_CRD_API_REFERENCE_DOCS) -api-dir=./api/v1beta1 -config=./hack/api-docs/config.json -template-dir=./hack/api-docs/template -out-file=./docs/api/v1beta1.md

.PHONY: docker-build
docker-build: build
	docker build -t ${IMG} .
	docker build -t ${PROXY_IMG} proxy

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}
	docker push ${PROXY_IMG}

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/base/crd | kubectl replace -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/base/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/base/manager && $(KUSTOMIZE) edit set image ghcr.io/doodlescheduling/keycloak-controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

TEST_PROFILE=keycloak-v20
CLUSTER=kind

.PHONY: kind-test
kind-test: ## Deploy including test
	kustomize build config/base/crd | kubectl --context kind-${CLUSTER} apply -f -	
	kubectl --context kind-${CLUSTER} -n keycloak-system delete pods --all
	kind load docker-image ${IMG} --name ${CLUSTER}
	kustomize build config/tests/cases/${TEST_PROFILE} --enable-helm | kubectl --context kind-${CLUSTER} apply -f -	
	kubectl --context kind-${CLUSTER} -n keycloak-system wait --for=condition=Ready pods -l control-plane=controller-manager -l app.kubernetes.io/managed-by!=Helm,verify!=yes --timeout=3m
	kubectl --context kind-${CLUSTER} -n keycloak-system wait --for=jsonpath='{.status.conditions[1].reason}'=PodCompleted pods -l app.kubernetes.io/managed-by!=Helm,verify=yes --timeout=3m

CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.12.0)
	cp config/base/crd/bases/* chart/keycloak-controller/crds/

GOLANGCI_LINT = $(GOBIN)/golangci-lint
.PHONY: golangci-lint
golangci-lint: ## Download golint locally if necessary
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2)

KUSTOMIZE = $(GOBIN)/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4.5.7)

ENVTEST = $(GOBIN)/setup-envtest
.PHONY: envtest
envtest: ## Download envtest-setup locally if necessary.
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

# go-install-tool will 'go install' any package $2 and install it to $1
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
env -i bash -c "GOBIN=$(GOBIN) PATH=$(PATH) GOPATH=$(shell go env GOPATH) GOCACHE=$(shell go env GOCACHE) go install $(2)" ;\
rm -rf $$TMP_DIR ;\
}
endef
