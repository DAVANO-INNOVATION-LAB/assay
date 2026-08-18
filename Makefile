IMG ?= quay.io/davano/assay-operator:0.1.0
NAMESPACE ?= assay-system
CONTROLLER_TOOLS_VERSION ?= v0.17.2

# Must match scanners.DefaultRegistry and scanners.ImageTag in
# internal/scanners/catalog.go.
SCANNER_REGISTRY ?= quay.io/davano
SCANNER_TAG ?= 0.1.0

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
# The single pin for both local and CI use: CI runs `make lint`, so there is no
# second version to drift. Installed with `go install`, which builds it against
# the local toolchain — golangci-lint errors out when the Go version it was
# built with is older than the one go.mod targets, which is what a prebuilt
# binary from the marketplace action would hit.
GOLANGCI_LINT_VERSION ?= v1.62.2

# Stamped into the standalone CLI. Override on release: make cli VERSION=v0.2.0
VERSION ?= dev
CLI_LDFLAGS ?= -X main.version=$(VERSION)

.PHONY: all
all: build

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CRDs and RBAC from kubebuilder markers.
	$(CONTROLLER_GEN) crd rbac:roleName=assay-manager-role paths=./... \
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

.PHONY: test-mlflow
test-mlflow: ## Live MLflow integration test (needs Docker + the mlflow image).
	go test -tags mlflow_live -run TestMLflowLive ./internal/modelsource/ -v

.PHONY: test-s3
test-s3: ## Live S3 resolver test against MinIO (needs Docker).
	go test -tags s3_live -run TestS3Live ./internal/resolver/ -v

.PHONY: test-live
test-live: test-mlflow test-s3 ## Every integration test that needs real services.

.PHONY: lint
lint: golangci-lint ## Run the linters CI runs.
	$(GOLANGCI_LINT) run ./...

##@ Build

.PHONY: build
build: fmt vet ## Build all binaries.
	go build -o bin/assay-manager ./cmd/manager
	go build -o bin/assay-runner ./cmd/runner
	go build -ldflags "$(CLI_LDFLAGS)" -o bin/assay ./cmd/assay

.PHONY: cli
cli: ## Build the standalone inspector CLI (make cli VERSION=v0.2.0).
	go build -ldflags "$(CLI_LDFLAGS)" -o bin/assay ./cmd/assay

# GOOS/GOARCH pairs shipped as release binaries.
CLI_PLATFORMS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: cli-release
cli-release: ## Cross-compile the CLI for every release platform into dist/.
	@mkdir -p dist
	@for platform in $(CLI_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=dist/assay-$(VERSION)-$$os-$$arch; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -ldflags "$(CLI_LDFLAGS)" -o $$out ./cmd/assay || exit 1; \
	done

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
	# Namespace first: everything below is created inside it.
	kubectl apply -f config/namespace.yaml
	kubectl apply -f config/rbac
	kubectl apply -f config/manager
	kubectl apply -f config/webhook

.PHONY: undeploy
undeploy:
	kubectl delete --ignore-not-found -f config/webhook
	kubectl delete --ignore-not-found -f config/manager
	kubectl delete --ignore-not-found -f config/rbac
	kubectl delete --ignore-not-found -f config/namespace.yaml

##@ Tools

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	@test -x $(CONTROLLER_GEN) || \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: golangci-lint
golangci-lint: $(LOCALBIN)
	@test -x $(GOLANGCI_LINT) || \
		GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
