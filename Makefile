# Qredin — identity and authorization platform
#
# `make verify` is the single gate that must pass before any commit.
# Release gating is described in docs/operations.md and plan §15.4.

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO             ?= go
MODULE         := github.com/qredin/qredin
BIN            := bin
GEN            := api/gen
VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT         ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

CMDS := qredin-server qredin-agent qredin-authz qredin qredin-operator

## ---------------------------------------------------------------------------
## Help
## ---------------------------------------------------------------------------

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_.-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## ---------------------------------------------------------------------------
## Code generation
## ---------------------------------------------------------------------------

.PHONY: proto
proto: ## Generate protobuf/gRPC code from api/proto (REQUIRED before first build)
	@command -v protoc >/dev/null || { echo "protoc not found: see docs/BUILD.md"; exit 1; }
	@command -v protoc-gen-go >/dev/null || { echo "protoc-gen-go not found: see docs/BUILD.md"; exit 1; }
	@command -v protoc-gen-go-grpc >/dev/null || { echo "protoc-gen-go-grpc not found: see docs/BUILD.md"; exit 1; }
	@mkdir -p $(GEN)
	protoc \
		--proto_path=api/proto \
		--go_out=$(GEN) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN) --go-grpc_opt=paths=source_relative \
		$$(find api/proto -name '*.proto')
	@echo "generated -> $(GEN)"

.PHONY: proto-check
proto-check:
	@test -d $(GEN) || { \
		echo ""; \
		echo "ERROR: generated protobuf code missing."; \
		echo "       Run 'make proto' first (see docs/BUILD.md)."; \
		echo ""; exit 1; }

## ---------------------------------------------------------------------------
## Build
## ---------------------------------------------------------------------------

.PHONY: build
build: proto-check $(addprefix $(BIN)/,$(CMDS)) ## Build all binaries

$(BIN)/%:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/$*

.PHONY: tidy
tidy: ## Reconcile go.mod/go.sum
	$(GO) mod tidy

## ---------------------------------------------------------------------------
## Test
## ---------------------------------------------------------------------------

.PHONY: test
test: ## Unit tests with race detector
	$(GO) test -race -count=1 ./...

.PHONY: test-core
test-core: ## Security-critical core only (no codegen required)
	$(GO) test -race -count=1 ./pkg/... ./internal/ca/... ./internal/policy/...

.PHONY: cover
cover: ## Coverage report for the security-critical core
	$(GO) test -count=1 -covermode=atomic -coverprofile=coverage.out ./pkg/... ./internal/...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: conformance
conformance: ## SPIFFE conformance suite (plan §15.1)
	$(GO) test -race -count=1 -tags=conformance ./test/conformance/...

.PHONY: integration
integration: ## Integration tests; requires QREDIN_TEST_POSTGRES_DSN
	@test -n "$$QREDIN_TEST_POSTGRES_DSN" || { echo "QREDIN_TEST_POSTGRES_DSN not set"; exit 1; }
	$(GO) test -race -count=1 -tags=integration -timeout=10m ./test/integration/...

.PHONY: fuzz-spiffeid
fuzz-spiffeid: ## Fuzz the SPIFFE ID parser (trust-boundary input)
	$(GO) test -run=XXX -fuzz=FuzzParseID -fuzztime=120s ./pkg/spiffeid

## ---------------------------------------------------------------------------
## Static analysis / supply chain
## ---------------------------------------------------------------------------

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) run mvdan.cc/gofumpt@latest -l -w .

.PHONY: lint
lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not found"; exit 1; }
	golangci-lint run ./...

.PHONY: vulncheck
vulncheck: ## Known-vulnerability scan (release gate)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: sbom
sbom: ## Generate SBOM (release gate, plan §15.4)
	@command -v syft >/dev/null || { echo "syft not found"; exit 1; }
	syft dir:. -o spdx-json=dist/sbom.spdx.json

## ---------------------------------------------------------------------------
## Gates
## ---------------------------------------------------------------------------

.PHONY: verify
verify: tidy vet lint test conformance vulncheck ## Full pre-commit gate

.PHONY: release-gate
release-gate: verify integration sbom ## Full pre-release gate (plan §15.4)

## ---------------------------------------------------------------------------
## Local non-production environment
## ---------------------------------------------------------------------------

.PHONY: dev-up
dev-up: ## Start the non-production stack (NEVER a production path)
	docker compose -f deploy/compose/docker-compose.yaml up -d --build

.PHONY: dev-down
dev-down:
	docker compose -f deploy/compose/docker-compose.yaml down -v

.PHONY: migrate
migrate: ## Apply database migrations
	$(GO) run ./cmd/qredin-server migrate --config $(or $(CONFIG),deploy/config/server.dev.yaml)

.PHONY: clean
clean:
	rm -rf $(BIN) $(GEN) dist coverage.out
