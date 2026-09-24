# Qredin Live Demo — Complete Step-by-Step Guide

---

## What You'll See in 10 Minutes

| Demo Part | What It Shows |
|-----------|---------------|
| **1. Start the Brain** | Central Identity Server issuing SVIDs |
| **2. Start the Guard** | Local agent on a machine, attesting identity |
| **3. Use the CLI** | Apply dynamic policy instantly |
| **4. Test Permission** | Check if an agent can do a specific action |
| **4. Simulate App** | App gets SVID with exact permissions via Unix socket |

---

## Prerequisites (One-Time Setup)

### System Requirements
- **OS**: Linux (Ubuntu 22.04+, Debian 12, RHEL 9) or macOS
- **Go**: 1.22+ installed
- **PostgreSQL**: 15+ (Docker is easiest)
- **Terminals**: 4 terminal windows/tabs

### Install Go (if not installed)
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y golang-go

# Or download from golang.org
# Verify:
go version  # Should show go1.22+
```

### Install PostgreSQL (Docker - Easiest)
```bash
# Run PostgreSQL in Docker
docker run -d \
  --name qredin-db \
  -e POSTGRES_PASSWORD=qredin123 \
  -e POSTGRES_DB=qredin \
  -p 5432:5432 \
  postgres:16

# Verify it's running
docker ps | grep qredin-db
```

---

## Step 1: Clone & Build (Run ONCE)

```bash
# 1. Clone the repository
git clone https://github.com/qredin/qredin.git
cd qredin

# 2. Download dependencies
go mod download

# 3. Build all three binaries
go build -o qredin-server ./cmd/qredin-server
go build -o qredin-agent ./cmd/qredin-agent
go build -o qredin-operator ./cmd/qredin-operator

# 4. Verify all three built successfully
ls -lh qredin-*
# Should show:
# qredin-server   (the Brain)
# qredin-agent    (the Local Guard)
# qredin-operator (the CLI)
```

---

## Step 2: Create Configuration File

Create a config file that all three binaries will use:

```bash
# Create config directory
mkdir -p /tmp/qredin-demo
cd /tmp/qredin-demo

# Create the config file
cat > server.yaml << 'EOF'
environment: development
log_level: info
log_format: text
trust_domain: demo.local

http:
  listen_addr: ":443"
  uds_path: "/tmp/qredin-demo/workload-api.sock"

postgres:
  dsn: "postgres://postgres:qredin123@localhost:5432/qredin?sslmode=disable"
  max_conns: 10
  min_conns: 2
  conn_timeout: "5s"

key_manager:
  type: disk
  dir: "/tmp/qredin-demo/keys"

# Operator settings (for demo)
operator:
  sso:
    enabled: false
  mfa:
    enabled: false
  rbac:
    enabled: false
  session:
    enabled: false
  rate_limit:
    enabled: true
    requests: 100
    window: "1m"
EOF

# Create directories
mkdir -p /tmp/qredin-demo/keys
mkdir -p /tmp/qredin-demo/workload-api.sock

echo "Config created at /tmp/qredin-demo/server.yaml"
```

---

## Step 3: Open 4 Terminal Windows

**You need 4 terminals open side-by-side:**

| Terminal | Purpose | Title |
|----------|---------|-------|
| **Terminal 1** | Run the Brain (`qredin-server`) | 🧠 BRAIN |
| **Terminal 2** | Run the Guard (`qredin-agent`) | 🛡️ GUARD |
| **Terminal 3** | Run the CLI (`qredin-operator`) | 🎮 CLI |
| **Terminal 4** | Simulate an App (curl) | 📱 APP |

**Arrange them so you can see all 4 at once.**

---

## Terminal 1: Start the BRAIN (qredin-server)

```bash
# In Terminal 1
cd /tmp/qredin-demo

# Copy binaries here (or use full path)
cp /path/to/qredin/qredin-server .
cp /path/to/qredin/qredin-operator .

# Run the Brain
./qredin-server --config server.yaml
```

**What you'll see:**
```
{"level":"info","msg":"starting Qredin Identity Server","trust_domain":"demo.local","uds_path":"/tmp/qredin-demo/workload-api.sock","grpc_listen":":443"}
{"level":"info","msg":"created authority","serial_number":"...","not_after":"2025-..."}
{"level":"info","msg":"listening on UDS socket","path":"/tmp/qredin-demo/workload-api.sock"}
{"level":"info","msg":"listening on administrative gRPC","address":":443"}
{"level":"info","msg":"health/metrics on","address":"localhost:9090"}
```

**Leave this running!** This is your central Brain.

---

## Terminal 2: Start the GUARD (qredin-agent)

```bash
# In Terminal 2
cd /tmp/qredin-demo

# Copy binary here
cp /path/to/qredin/qredin-agent .

# Run the Guard (Local Guard on this machine)
./qredin-agent --config server.yaml
```

**What you'll see:**
```
{"level":"info","msg":"starting Qredin Node Agent","node_id":"...","trust_domain":"demo.local","server":"localhost:443"}
{"level":"info","msg":"starting reconnect loop"}
{"level":"info","msg":"connected to identity server"}
{"level":"info","msg":"connected to identity server"}
```

**Leave this running!** This is your Local Guard on this machine.

---

## Terminal 3: Use the CLI (qredin-operator)

```bash
# In Terminal 3
cd /tmp/qredin-demo

# The CLI is already copied from Terminal 1

# First, let's see what the CLI can do
./qredin-operator --config server.yaml --help

# Check if server is healthy
./qredin-operator --config server.yaml health

# List registered nodes (should show the agent we just started)
./qredin-operator --config server.yaml node list
```

**What you'll see:**
```
# Health check
{"status":"ok"}

# Node list (shows your agent)
ID                                    NODE ID                           STATUS
spiffe://demo.local/node/...          spiffe://demo.local/node/...      active
```

---

## Terminal 4: The Magic — Live Policy Change

### Step 4a: Create a Dynamic Policy

```bash
# In Terminal 3 (CLI terminal)

# Create a policy that allows EXACTLY one operation:
# "Agent can READ from demo-table ONLY during business hours"
cat > demo-policy.yaml << 'EOF'
policies:
  - name: demo-dynamic-policy
    scope:
      tenant: platform
      environment: development
      trust_domain: demo.local
    rules:
      - id: allow-read-demo-table
        effect: allow
        action: "read"
        resource: "demo-table"
        conditions:
          - "time in business_hours"
          - "identity == 'spiffe://demo.local/demo-app'"
      - id: deny-all-else
        effect: deny
        action: "*"
        resource: "*"
EOF

# Apply the policy INSTANTLY (no restart needed!)
./qredin-operator --config server.yaml policy apply -f demo-policy.yaml
```

**What you'll see:**
```
Policy applied successfully: demo-dynamic-policy (version 1)
```

### Step 4b: Test the Permission

```bash
# Test if our demo-app can READ demo-table
./qredin-operator --config server.yaml authz check \
  --identity spiffe://demo.local/demo-app \
  --action read \
  --resource demo-table
```

**Output:**
```
DECISION: ALLOW
Policy: demo-dynamic-policy
Rule: allow-read-demo-table
Reason: All conditions met
```

### Step 4c: Test a DENIED Permission

```bash
# Try to WRITE (not allowed in policy)
./qredin-operator --config server.yaml authz check \
  --identity spiffe://demo.local/demo-app \
  --action write \
  --resource demo-table

# Try to access a different table
./qredin-operator --config server.yaml authz check \
  --identity spiffe://demo.local/demo-app \
  --action read \
  --resource other-table
```

**Output:**
```
DECISION: DENY
Reason: No matching allow rule (explicit deny)

DECISION: DENY
Reason: No matching allow rule (explicit deny)
```

**🎉 This is the magic!** Policy changed → instant effect. No restart. The agent gets new permissions on next request.

---

## Terminal 4: Simulate an App Getting an SVID

### Step 5: App Talks to Local Guard via Unix Socket

```bash
# In Terminal 4 (APP terminal)
cd /tmp/qredin-demo

# The app talks to the LOCAL GUARD (not the central server!)
# via Unix Domain Socket (UDS)

# 1. Check the socket exists
ls -la /tmp/qredin-demo/workload-api.sock
# Should show: srw-rw-rw- ... /tmp/qredin-demo/workload-api.sock

# 2. App asks Guard for SVID (via Workload API)
# This is what your app does automatically via SDK
curl --unix-socket /tmp/qredin-demo/workload-api.sock \
  http://localhost/workload.spiffe.io/v1/WorkloadAPI
```

**What you'll see (JSON response with SVID):**
```json
{
  "svids": [
    {
      "spiffe_id": "spiffe://demo.local/demo-app",
      "cert_chain": ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
      "hint": "demo-app"
    }
  ],
  "trust_domain": "demo.local"
}
```

**This is the SVID!** It contains:
- **Identity**: `spiffe://demo.local/demo-app`
- **Certificate**: For mTLS connections
- **Private key**: For signing (never leaves this machine)
- **Embedded permissions**: Only what policy allows

---

## Step 6: Show mTLS in Action (Optional)

```bash
# In Terminal 3, check the audit log (what happened)
./qredin-operator --config server.yaml audit tail

# Check server health/metrics
curl http://localhost:9090/healthz
curl http://localhost:9090/readyz
curl http://localhost:9090/metrics
```

**Output:**
```
# Health
{"status":"ok"}

# Ready (checks DB + agent)
{"status":"ready","conns_total":10,"conns_idle":8,"conns_acquired":2,"max_conns":10}

# Metrics (Prometheus format)
qredin_db_conns_total{direction="total"} 10
qredin_db_conns_idle{direction="idle"} 8
qredin_db_conns_acquired{direction="acquired"} 2
```

---

## Complete Command Reference (Cheat Sheet)

### The Three Binaries

| Binary | Command | Purpose |
|--------|---------|---------|
| **Brain** | `./qredin-server --config server.yaml` | Run central Identity Server |
| **Guard** | `./qredin-agent --config server.yaml` | Run on EACH machine |
| **CLI** | `./qredin-operator --config server.yaml <cmd>` | Your remote control |

### CLI Commands

| Command | What It Does |
|---------|--------------|
| `./qredin-operator --config server.yaml health` | Check server health |
| `./qredin-operator --config server.yaml node list` | List all registered agents |
| `./qredin-operator --config server.yaml policy apply -f policy.yaml` | Apply policy INSTANTLY |
| `./qredin-operator --config server.yaml policy get <name>` | View a policy |
| `./qredin-operator --config server.yaml authz check --identity X --action Y --resource Z` | Test if allowed |
| `./qredin-operator --config server.yaml audit tail` | Watch audit log live |
| `./qredin-operator --config server.yaml backup` | Create encrypted backup |
| `./qredin-operator --config server.yaml rotate-key` | Rotate CA keys |
| `./qredin-operator --config server.yaml --version` | Show version |

### App Integration (What Your App Does)

```bash
# App gets SVID from LOCAL Guard (not central server!)
curl --unix-socket /tmp/qredin-demo/workload-api.sock \
  http://localhost/workload.spiffe.io/v1/WorkloadAPI

# Returns SVID with certificate + private key + permissions
# App uses this for mTLS connections automatically
```

---

## Complete Architecture (What You Just Built)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DEMO ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TERMINAL 1                    TERMINAL 2                          │
│  ┌─────────────────┐             ┌─────────────────┐              │
│  │ qredin-server   │◄── gRPC ──► │ qredin-agent    │              │
│  │ (THE BRAIN)     │   mTLS      │ (LOCAL GUARD)   │              │
│  │                 │             │                 │              │
│  │ • Issues SVIDs  │             │ • Attests node  │              │
│  │ • Signs certs   │             │ • Gets SVIDs    │              │
│  │ • Evaluates     │             │ • Hands SVIDs   │              │
│  │   policies      │             │   to apps       │              │
│  │ • PostgreSQL    │             │ • Unix socket   │              │
│  └─────────────────┘             └────────┬────────┘              │
│                                           │                        │
│                    ┌──────────────────────┼──────────────────┐    │
│                    │                      │                  │    │
│                    ▼                      ▼                  ▼    │
│           ┌───────────────┐      ┌───────────────┐  ┌───────────┐│
│           │  TERMINAL 3   │      │  TERMINAL 4   │  │  POSTGRES ││
│           │  qredin-      │      │  curl --unix- │  │  (State)  ││
│           │  operator     │      │  socket       │  │           ││
│           │  (CLI)        │      │  (App sim)    │  │           ││
│           │               │      │               │  │           ││
│           │ • Apply policy│      │ • Gets SVID   │  │ • Nodes   ││
│           │ • Check perms │      │ • Uses SVID   │  │ • Policies││
│           │ • Audit log   │      │   for mTLS    │  │ • Audit   ││
│           └───────────────┘      └───────────────┘  └───────────┘│
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What Just Happened (The Story)

| Step | What Happened | Why It Matters |
|------|---------------|----------------|
| 1. Started Brain | Central authority came online | Central authority ready |
| 2. Started Guard | Local agent attested itself | Machine proves identity |
| 3. Guard ↔ Brain | Secure mTLS connection | Secure channel established |
| 4. CLI applied policy | Dynamic policy live instantly | **No restart!** |
| 5. CLI checked permission | Real-time policy evaluation | **Dynamic!** |
| 6. App got SVID | App got permission slip | **Row-level perms!** |
| 6. SVID has exact perms | Only allowed operations | **Blast radius = 1 row** |

---

## Common Issues & Fixes

| Problem | Fix |
|---------|-----|
| `connection refused` to PostgreSQL | Check Docker: `docker ps`, restart: `docker restart qredin-db` |
| `permission denied` on socket | `sudo chmod 666 /tmp/qredin-demo/workload-api.sock` |
| `config validation failed` | Check `server.yaml` syntax, paths exist |
| Agent can't connect to server | Check firewall, port 443, server running in Terminal 1 |
| `policy apply` fails | Check YAML syntax, run `./qredin-operator --config server.yaml policy get` |

---

## Cleanup (When Done)

```bash
# Stop all processes (Ctrl+C in each terminal)
# Then clean up:
docker stop qredin-db && docker rm qredin-db
rm -rf /tmp/qredin-demo
```

---

## What to Say When Demoing

> **"Watch this — I'm going to give an AI agent permission to delete exactly ONE row from a database, and nothing else."**
> 
> 1. **Start Brain + Guard** (30 sec) — "Central brain + local guard on every machine"
> 2. **Apply policy via CLI** — "Dynamic policy, instant effect, no restart"
> 2. **Check permission** — "Real-time evaluation: ALLOW read, DENY write"
> 3. **App gets SVID** — "App gets hourly-expiring permission slip with exact permissions"
> 4. **Show audit log** — "Immutable trail: who, what, when, from where"
> 
> **"Old way: admin password = entire DB at risk. Qredin way: exact permission for exact row = blast radius = 1 row."**

---

## Files Created in This Demo

```
/tmp/qredin-demo/
├── server.yaml              # Config for all 3 binaries
├── demo-policy.yaml         # Dynamic policy
├── qredin-server            # Binary: The Brain
├── qredin-agent             # Binary: The Guard
├── qredin-operator          # Binary: The CLI
├── keys/                    # Key manager directory
└── workload-api.sock        # Unix socket (created by agent)
```

---

## Next Steps for Production

| Step | What to Do |
|------|------------|
| 1. **HA Setup** | Run 2+ servers, use PostgreSQL HA |
| 2. **HSM/KMS** | Replace disk key manager with AWS KMS / Vault / CloudHSM |
| 3. **K8s Deployment** | Deploy agent as DaemonSet, server as Deployment |
| 4. **Monitoring** | Connect Prometheus/Grafana to `:9090/metrics` |
| 5. **Backup/Restore** | Schedule daily backups, test RPO/RTO |
| 6. **Policies** | Define your real dynamic policies as code |

---

*Demo Version: 1.0 | Qredin v1.x | Run time: ~10 minutes*