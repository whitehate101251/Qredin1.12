# 🚀 Qredin — SPIFFE Zero-Trust Identity Platform

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-blue.svg)](https://golang.org)
[![Security Architecture](https://img.shields.io/badge/SPIFFE-Native-green.svg)](https://spiffe.io)
[![License](https://img.shields.io/badge/License-Apache--2.0-orange.svg)](LICENSE)

---

## 📌 1. What is Qredin?

**Qredin** is an enterprise-grade, high-performance **Zero-Trust Workload Identity Platform** built natively around the **SPIFFE (Secure Production Identity Framework for Everyone)** specifications.

In modern cloud-native environments, microservices, databases, and background agents cannot rely on static IP addresses or long-lived API keys. Qredin solves fundamental workload authentication ("Who are you?"):

- **Node & Workload Attestation**: Cryptographically verifies host machines and local processes (Linux Unix sockets, Docker containers, Kubernetes Pods, Systemd services).
- **Dynamic SVID Issuance**: Mints short-lived, dynamically rotated **X.509 SVIDs** (SPIFFE Verifiable Identity Documents) and trust domain bundles.
- **SPIFFE Workload API**: Exposes the standard SPIFFE Workload API gRPC interface over Unix domain sockets.

Qredin is engineered with **zero third-party dependencies** in its security-critical PKI validation core, leveraging Go's standard library (`crypto/x509`, `encoding/json`, `net/url`) for maximum auditability, performance, and fuzzing guarantees.

---

## 🏗️ 2. Architecture & Service Components

Qredin's core identity engine lives inside the **`authentication/`** service package, backed by shared base libraries in **`pkg/`**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                               AUTHENTICATION SERVICE (authentication/)                      │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│  • Node & Workload Attestation (Unix, Docker, Kubernetes, Systemd)                         │
│  • Certificate Authority (CA) & X.509 SVID Issuance                                         │
│  • Identity Registration Registry & Workflow Approvals                                      │
│  • SPIFFE Workload API gRPC Streaming                                                       │
│                                                                                             │
│  Binaries:                                                                                  │
│  - authentication/cmd/qredin-server (Identity Server)                                      │
│  - authentication/cmd/qredin-agent (Node Host Agent)                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                               ▲
                                               │ (Shared Primitives)
                                               │
┌──────────────────────────────────────────────┴──────────────────────────────────────────────┐
│                               SHARED BASE LIBRARIES (pkg/)                                  │
│  • pkg/spiffeid (SPIFFE ID Parser)             • pkg/clock (Monotonic Time Provider)       │
│  • pkg/bundle (Trust Domain Bundles)           • pkg/testsupport (PKI Mocks & Test Suite)    │
│  • pkg/x509svid (X.509 SVID Profile Verifier)                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 💻 3. The Executables & Binaries

| Binary | Location | Primary Purpose | Where It Runs |
| :--- | :--- | :--- | :--- |
| **`qredin-server`** | `authentication/cmd/qredin-server` | Central **Identity & CA Server**. Attests nodes, manages trust domains, and signs X.509 SVIDs. | **Control Plane** (1 or HA cluster) |
| **`qredin-agent`** | `authentication/cmd/qredin-agent` | **Host Node Agent**. Attests local host processes/containers and streams SVIDs over Unix socket. | **Every Machine** running workloads |
| **`qredin`** | `cmd/qredin` | **Unified Admin CLI**. Management client for identity registration entries and tokens. | **Admin Laptop / Bastion** |
| **`qredin-operator`**| `cmd/qredin-operator` | **Operator CLI**. Configuration validator and operational automation utility. | **DevOps / CI/CD Pipeline** |

---

## 📁 4. Comprehensive Directory Structure ("Where is What and Why")

```
.
├── api/                                  # Protobuf gRPC interface definitions & generated Go code
│   └── workloadapi/v1/                   # Official SPIFFE Workload API v1 proto & gRPC stubs
│
├── authentication/                       # AUTHENTICATION & IDENTITY SERVICE (AuthN)
│   ├── cmd/                              # AuthN Service Binaries
│   │   ├── qredin-agent/                 # Node Agent daemon entrypoint (main.go)
│   │   └── qredin-server/                # Identity Server daemon entrypoint (main.go)
│   ├── config/                           # Configuration models & loading logic for AuthN
│   └── internal/                         # Private AuthN implementation packages
│       ├── agent/                        # Agent session management & UDS handshakes
│       ├── attestation/                  # Attestation facts & attestor implementations
│       │   ├── node/                     # Node attestation (join tokens, K8s TokenReview)
│       │   └── workload/                 # Workload attestors (Unix UDS, Docker, K8s, Systemd)
│       ├── ca/                           # X.509 CA state machine, rotation, & SVID issuer
│       ├── keymanager/                   # CA private key protection (Disk & AWS KMS / Cloud KMS)
│       ├── registration/                 # Identity registration registry & entry lifecycle
│       ├── server/                       # Workload identity resolution engine
│       ├── store/                        # AuthN PostgreSQL repositories (registrations, audit)
│       ├── version/                      # Build version information
│       └── workloadapi/                  # gRPC Workload API socket server & credential streaming
│
├── cmd/                                  # CLI MANAGEMENT TOOLING
│   ├── qredin/                           # Unified Admin CLI
│   └── qredin-operator/                  # Operator & Config Validator CLI
│
├── deploy/                               # Deployment configurations & sample YAMLs
│   └── config/                           # Environment configs for dev, staging, and production
│
├── docs/                                 # Technical documentation & Architecture Decision Records
│   ├── adr/                              # Accepted ADRs (e.g. 0002-first-party-spiffe-core.md)
│   ├── architecture.md                   # Deep-dive platform architecture guide
│   └── attestation.md                    # Attestation mechanics & selector documentation
│
└── pkg/                                  # SHARED REUSABLE BASE PACKAGES
    ├── bundle/                           # Trust domain bundle management & JWK serialization
    ├── clock/                            # Universal monotonic clock provider
    ├── spiffeid/                         # SPIFFE ID parsing, canonicalization, & validation
    ├── testsupport/                      # Shared integration test fixtures & PKI mocks
    └── x509svid/                         # X.509 SVID profile validator & chain verifier
```

---

## ⚡ 5. How to Use Qredin (Step-by-Step Quickstart)

### Step 1: Build Executables
Compile the binaries into `./bin/`:

```bash
mkdir -p bin
go build -o bin/qredin-server ./authentication/cmd/qredin-server
go build -o bin/qredin-agent ./authentication/cmd/qredin-agent
go build -o bin/qredin-operator ./cmd/qredin-operator
go build -o bin/qredin ./cmd/qredin
```

---

### Step 2: Start PostgreSQL Database
Qredin requires PostgreSQL 15+ for persistent storage:

```bash
docker run -d \
  --name qredin-postgres \
  -p 5432:5432 \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=postgres \
  postgres:16
```

---

### Step 3: Create Server Configuration
Create a minimal development configuration file `server.dev.yaml`:

```yaml
environment: development
trust_domain: demo.local
log_level: info
log_format: text

http:
  listen_addr: "127.0.0.1:9090"
  uds_path: "/tmp/qredin.sock"

postgres:
  dsn: "postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable"
  max_conns: 10
  min_conns: 2

key_manager:
  type: disk
  dir: "/tmp/qredin-keys"

server:
  authority_ttl: "24h"
```

---

### Step 4: Launch `qredin-server`
Start the central Identity & CA Server:

```bash
./bin/qredin-server --config server.dev.yaml
```
*Console output:*
```
INFO starting Qredin Identity Server trust_domain=demo.local uds_path=/tmp/qredin.sock
INFO created authority serial_number=... not_after=...
INFO listening on UDS socket path=/tmp/qredin.sock
```

---

### Step 5: Fetch Identity SVIDs via Workload API
Workloads query the local Unix Domain Socket (`/tmp/qredin.sock`) implementing the standard SPIFFE Workload API:

```bash
# Query the Workload API socket directly
curl --unix-socket /tmp/qredin.sock http://localhost/workload.spiffe.io/v1/WorkloadAPI
```
*Response*: Returns the workload's X.509 SVID certificate chain, private key, and SPIFFE trust bundle!

---

## 🧪 6. Verification & Testing

```bash
# Run static analysis and vet check across all packages
go vet ./...

# Run the complete test suite with race detection enabled
go test -race -count=1 ./...
```

---

## 📄 License

Qredin is licensed under the [Apache 2.0 License](LICENSE).
