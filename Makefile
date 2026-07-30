IMG ?= quay.io/zeus-security/zeus-operator:0.1.0
NAMESPACE ?= zeus-system
CONTROLLER_TOOLS_VERSION ?= v0.17.2

# Must match scanners.DefaultRegistry and scanners.ImageTag in
# internal/scanners/catalog.go.
SCANNER_REGISTRY ?= quay.io/zeus-security
SCANNER_TAG ?= 0.1.0

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

.PHONY: all
all: build

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CRDs and RBAC from kubebuilder markers.
	$(CONTROLLER_GEN) crd rbac:roleName=zeus-manager-role paths=./... \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac

.PHONY: generate
generate: controller-gen ## Generate DeepCopy methods.
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test: fmt vet ## Run the unit test suite.
	go test ./... -race -coverprofile=cover.out

.PHONY: cover
cover: test ## Show per-package coverage.
	go tool cover -func=cover.out

##@ Build

.PHONY: build
build: fmt vet ## Build both binaries.
	go build -o bin/zeus-manager ./cmd/manager
	go build -o bin/zeus-runner ./cmd/runner

.PHONY: docker-build
docker-build: ## Build the operator image.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push:
	docker push $(IMG)

##@ Scanner images

.PHONY: scanners
scanners: ## Build every scanner image with databases baked in.
	$(MAKE) -C scanners build REGISTRY=$(SCANNER_REGISTRY) TAG=$(SCANNER_TAG)

.PHONY: scanners-push
scanners-push:
	$(MAKE) -C scanners push REGISTRY=$(SCANNER_REGISTRY) TAG=$(SCANNER_TAG)

.PHONY: scanners-smoke
scanners-smoke: ## Run the scanner images against a planted artifact, air-gapped.
	$(MAKE) -C scanners smoke REGISTRY=$(SCANNER_REGISTRY) TAG=$(SCANNER_TAG)

.PHONY: scanner-fixtures
scanner-fixtures: ## Refresh the recorded real scanner output used by the parser tests.
	./hack/capture-scanner-fixtures.sh $(SCANNER_REGISTRY) $(SCANNER_TAG)

.PHONY: mirror-list
mirror-list: ## Print every image to mirror into an air-gapped registry.
	@echo $(IMG)
	@$(MAKE) -s -C scanners mirror REGISTRY=$(SCANNER_REGISTRY) TAG=$(SCANNER_TAG)

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the cluster.
	kubectl apply -f config/crd/bases

.PHONY: uninstall
uninstall:
	kubectl delete --ignore-not-found -f config/crd/bases

.PHONY: deploy
deploy: install ## Deploy the operator.
	kubectl apply -f config/rbac
	kubectl apply -f config/manager
	kubectl apply -f config/webhook

.PHONY: undeploy
undeploy:
	kubectl delete --ignore-not-found -f config/webhook
	kubectl delete --ignore-not-found -f config/manager
	kubectl delete --ignore-not-found -f config/rbac

##@ Tools

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	@test -x $(CONTROLLER_GEN) || \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
