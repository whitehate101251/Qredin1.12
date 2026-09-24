# Qredin: What Is What (Super Simple)

---

## The Three Pieces (Binaries)

You build **three executable programs** from this codebase:

| Binary | What It Is | Where It Runs | Code Location |
|--------|------------|---------------|---------------|
| **`qredin-server`** | The **Brain** (Identity Server) | **ONE central machine** | `cmd/qredin-server/main.go` |
| **`qredin-agent`** | The **Local Guard** (Node Agent) | **EVERY machine** that runs workloads | `cmd/qredin-agent/main.go` |
| **`qredin-operator`** | The **Remote Control** (CLI) | **Your laptop/bastion** | `cmd/qredin-operator/main.go` |

---

## What Each Piece Does (In Human Terms)

### 1. `qredin-server` = The Brain (Identity Server)
**Runs on: ONE central server (control plane)**

| Responsibility | Code Location |
|----------------|---------------|
| **Issues SVIDs** (the dynamic permission slips) | `internal/ca/node_issuer.go` |
| **Signs certificates** (mTLS keys) | `internal/ca/ca.go`, `internal/keymanager/` |
| **Evaluates policies** (decides what each agent can do) | `internal/policy/`, `internal/store/policy.go` |
| **Stores state** (who's registered, policies, audit logs) | `internal/store/` (PostgreSQL) |
| **Runs the CA** (certificate authority in HSM) | `internal/ca/`, `internal/keymanager/kms.go` |

**Think of it as**: The central authority that says "Yes, this agent can do X" and signs the permission slip.

---

### 2. `qredin-agent` = The Local Guard (Node Agent)
**Runs on: EVERY machine that runs your apps/agents**

| Responsibility | Code Location |
|---------------|---------------|
| **Proves "I am this machine"** (attestation) | `internal/attestation/node/` |
| **Talks to Brain** to get SVIDs | `internal/agent/session.go` |
| **Hands out SVIDs** to local apps via Unix socket | `internal/workloadapi/`, `internal/agent/` |
| **Renews SVIDs** automatically before expiry | `internal/agent/session.go` |
| **Attests workloads** (proves "this process is App X") | `internal/attestation/workload/` |

**Think of it as**: The local representative on each machine. Apps talk to IT (not the central brain) to get their permission slips.

---

### 3. `qredin-operator` = The Remote Control (CLI)
**Runs on: Your laptop / bastion host**

| Responsibility | Code Location |
|---------------|---------------|
| **Apply policies** (make rules live instantly) | `cmd/qredin-operator/main.go` |
| **Rotate keys** | `cmd/qredin-operator/main.go` |
| **Backup/restore** | `cmd/qredin-operator/main.go` |
| **Check status / audit logs** | `cmd/qredin-operator/main.go` |
| **Approve/revoke nodes** | `cmd/qredin-operator/main.go` |

**Think of it as**: Your remote control. You never touch the server directly—you use this.

---

## Where Does mTLS / SVID Issuing Happen?

| Part | Code | What It Does |
|------|------|--------------|
| **CA (Certificate Authority)** | `internal/ca/ca.go`, `internal/ca/node_issuer.go` | Creates the root/intermediate certificates |
| **Key Manager** | `internal/keymanager/` (disk, AWS KMS) | Stores private keys securely (HSM) |
| **SVID Issuance** | `internal/ca/node_issuer.go` | Takes attested identity → creates SVID with permissions |
| **mTLS Handshake** | `internal/workloadapi/`, `pkg/x509svid/` | Apps present SVIDs, peers verify via mTLS |
| **Workload API** | `internal/workloadapi/`, `api/workloadapi/v1/` | Unix socket where apps ask for SVIDs |

**Simple flow**:
```
App asks Agent (Unix socket) → Agent asks Server → Server signs SVID → Agent gives SVID to App
                                                      ↑
                                              Keys in HSM (never leave)
```

---

## Where to Run What (Deployment Map)

```
┌─────────────────────────────────────────────────────────────────┐
│                     PRODUCTION DEPLOYMENT                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐         ┌─────────────────────────────┐   │
│  │  CONTROL PLANE  │         │       DATA PLANE             │   │
│  │  (1 machine)    │         │    (N machines)              │   │
│  │                 │         │                              │   │
│  │  qredin-server  │◄───────►│  qredin-agent  │ App A       │   │
│  │  (Brain)        │  gRPC   │  (Local Guard) │ App B       │   │
│  │                 │  mTLS   │                │ App C       │   │
│  │  PostgreSQL     │         │  qredin-agent  │ App D       │   │
│  │  (State)        │         │  (Local Guard) │ App E       │   │
│  │                 │         │                │ ...         │   │
│  │  HSM/Vault      │         │  qredin-agent  │             │   │
│  │  (Keys)         │         │  (Local Guard) │             │   │
│  └─────────────────┘         └─────────────────────────────┘   │
│                                                                  │
│  YOUR LAPTOP:  qredin-operator  ──────►  qredin-server          │
│                  (Remote Control)      (via admin gRPC)         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Component | Count | Where |
|-----------|-------|-------|
| `qredin-server` | **1** (or HA pair) | Dedicated control plane node |
| `qredin-agent` | **1 per machine** | Every VM, bare metal, K8s node |
| `qredin-operator` | **1 per admin** | Your laptop / bastion |
| PostgreSQL | 1 (or HA) | Same as server or managed |
| HSM/Vault | 1 | Dedicated or cloud KMS |

---

## Is `qredin` a CLI Tool?

**`qredin` itself doesn't exist as a single binary.**

You get **three separate binaries**:

```bash
# After building:
ls -la qredin-*
# qredin-server      # The Brain (run as service)
# qredin-agent       # The Guard (run on every node)
# qredin-operator    # The CLI (run on your laptop)
```

**`qredin-operator` IS the CLI tool** — that's what you run manually.

```bash
# Examples of CLI usage:
qredin-operator --config server.yaml policy apply -f policy.yaml
qredin-operator --config server.yaml rotate-key
qredin-operator --config server.yaml backup
qredin-operator --config server.yaml audit tail
qredin-operator --config server.yaml node list
```

---

## How to Demo It to Someone (5-Minute Demo)

### Prerequisites (30 seconds)
```bash
# 1. Build
go build ./cmd/qredin-server
go build ./cmd/qredin-agent
go build ./cmd/qredin-operator

# 2. Start PostgreSQL (Docker)
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=secret postgres:16

# 3. Config (minimal)
cat > server.yaml <<EOF
environment: development
trust_domain: demo.local
http:
  listen_addr: ":443"
  uds_path: "/tmp/qredin.sock"
postgres:
  dsn: "postgres://postgres:secret@localhost:5432/postgres?sslmode=disable"
key_manager:
  type: disk
  dir: /tmp/qredin/keys
EOF
```

### Live Demo (4 minutes)

**Terminal 1: Start Brain**
```bash
./qredin-server --config server.yaml
# Output: "starting Qredin Identity Server... listening on UDS socket"
```

**Terminal 2: Start Guard (on same machine for demo)**
```bash
./qredin-agent --config server.yaml
# Output: "starting Qredin Node Agent... connected to identity server"
```

**Terminal 3: Your Remote Control**
```bash
# See what's registered
./qredin-operator --config server.yaml node list

# Create a dynamic policy (instant!)
cat > demo-policy.yaml <<EOF
policies:
  - name: demo
    rules:
      - id: allow-read
        effect: allow
        action: "read"
        resource: "demo-table"
        conditions:
          - "time in business_hours"
EOF

# Apply INSTANTLY
./qredin-operator --config server.yaml policy apply -f demo-policy.yaml

# Test the permission
./qredin-operator --config server.yaml authz check \
  --identity spiffe://demo.local/demo-app \
  --action read --resource demo-table
# Output: ALLOW
```

**Terminal 4: Simulate an App Getting SVID**
```bash
# App talks to local Agent via Unix socket
# (In real app, this is automatic via SDK)
curl --unix-socket /tmp/qredin.sock http://localhost/workload.spiffe.io/v1/WorkloadAPI
# Returns: SVID with permissions embedded!
```

---

## The One Diagram to Show People

```
┌─────────────┐     1. App asks          ┌─────────────┐
│   YOUR APP  │ ──────────────────────►  │ qredin-agent│
│  (needs ID) │   "Give me an SVID"      │ (Local Guard)│
└─────────────┘                          └──────┬──────┘
                                                │
                                                │ 2. "Prove who you are"
                                                ▼
                                         ┌─────────────┐
                                         │ qredin-server│
                                         │  (The Brain)  │
                                         │               │
                                         │ • Verifies    │
                                         │ • Checks policy│
                                         │ • Signs SVID   │
                                         └──────┬────────┘
                                                │
                                                │ 3. "Here's your SVID"
                                                │    (with exact permissions)
                                                ▼
                                         ┌─────────────┐
                                         │   YOUR APP  │
                                         │  (uses SVID  │
                                         │   for mTLS)  │
                                         └─────────────┘
```

---

## One-Liner for Stakeholders

> **Qredin = 3 programs.**
> 1. **Server** (central brain) — issues permission slips
> 2. **Agent** (on every machine) — hands slips to apps
> 3. **Operator** (your CLI) — you control the rules
> 
> **Apps get hourly-expiring, row-level permission slips automatically.**
> **You change rules → instant effect. No restarts. Ever.**

---

## File Map (If They Ask "Where's the Code?")

| Feature | File |
|---------|------|
| Server main | `cmd/qredin-server/main.go` |
| Agent main | `cmd/qredin-agent/main.go` |
| CLI main | `cmd/qredin-operator/main.go` |
| SVID issuing | `internal/ca/node_issuer.go` |
| mTLS/SVID types | `pkg/x509svid/` |
| Policy engine | `internal/policy/` |
| Attestation | `internal/attestation/` |
| Workload API | `internal/workloadapi/` |
| Database | `internal/store/` |
| Keys/HSM | `internal/keymanager/` |