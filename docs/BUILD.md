# Qredin Build Guide

This document describes how to build Qredin binaries from source.

## Prerequisites

- Go 1.23 or later
- `protoc` and the Go protobuf plugins:
  - `protoc-gen-go`
  - `protoc-gen-go-grpc`
- Optional: `golangci-lint`, `syft`, `govulncheck`

## Install protoc plugins

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

## Generate protobuf/gRPC code

Qredin uses generated protobuf/gRPC bindings from `api/proto`. This must be run before the first build.

```bash
make proto
```

This generates code into `api/gen/`.

## Build all binaries

```bash
make build
```

Binaries are placed in `bin/`:

- `bin/qredin-server` — Identity Server
- `bin/qredin-agent` — Node Agent
- `bin/qredin-authz` — Authorization Service
- `bin/qredin` — Operator CLI dispatcher
- `bin/qredin-operator` — Operator CLI

## Build a single binary

```bash
make bin/qredin-server
```

## Verify

Run the full pre-commit gate:

```bash
make verify
```

This runs `tidy`, `vet`, `lint`, `test`, `conformance`, and `vulncheck`.

## Local non-production environment

```bash
make dev-up
make dev-down
```

## Apply database migrations

```bash
make migrate CONFIG=deploy/config/server.dev.yaml
```