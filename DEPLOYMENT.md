# Qredin Production Deployment Guide

---

## The Critical Difference

| | **Demo (One Laptop)** | **Production** |
|---|----------------------|----------------|
| **qredin-server** | Runs on your laptop | **Dedicated control plane VM(s)** |
| **qredin-agent** | Runs on your laptop | **Every application VM / K8s node** |
| **qredin-operator** | Runs on your laptop | **Your laptop / bastion (same)** |
| **PostgreSQL** | Docker on laptop | **Managed DB (RDS/CloudSQL) or HA cluster** |
| **Keys** | Disk (`/tmp/...`) | **HSM / Cloud KMS / Vault** |
| **Network** | localhost | **Private VPC, mTLS, load balancers** |

---

## Production Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRODUCTION DEPLOYMENT                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    CONTROL PLANE (Managed)                           │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │   │
│  │  │ qredin-server   │  │ qredin-server   │  │ qredin-server   │     │   │
│  │  │ (Primary)       │  │ (Replica 1)     │  │ (Replica 2)     │     │   │
│  │  │                 │  │                 │  │                 │     │   │
│  │  │ Port: 443 (gRPC)│  │ Port: 443       │  │ Port: 443       │     │   │
│  │  │ Port: 9090 (HB) │  │ Port: 9090      │  │ Port: 9090      │     │   │
│  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘     │   │
│  │           │                    │                    │              │   │
│  │           └────────────────────┼────────────────────┘              │   │
│  │                                ▼                                  │   │
│  │                    ┌─────────────────────┐                        │   │
│  │                    │  PostgreSQL HA      │                        │   │
│  │                    │  (Primary + Replicas)                        │   │
│  │                    │  Port: 5432                              │   │
│  │                    └─────────────────────┘                        │   │
│  │                           │                                      │   │
│  │                    ┌──────┴──────┐                               │   │
│  │                    ▼             ▼                               │   │
│  │           ┌─────────────┐ ┌─────────────┐                        │   │
│  │           │  HSM /      │ │  Load       │                        │   │
│  │           │  Cloud KMS  │ │  Balancer   │                        │   │
│  │           │  (Keys)     │ │  (TLS Term) │                        │   │
│  │           └─────────────┘ └─────────────┘                        │   │
│  └─────────────────────────────────────────────────────────────┘   │   │
│                                    │                                │   │
│                                    │ mTLS (gRPC)                     │   │
│                                    ▼                                │   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    DATA PLANE (Auto-scaling)                 │   │
│  │                                                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │   │
│  │  │  VM / Node  │  │  VM / Node  │  │  VM / Node  │  ...  │   │
│  │  │  (App Tier) │  │  (App Tier) │  │  (DB Tier)  │       │   │
│  │  │             │  │             │  │             │       │   │
│  │  │ qredin-agent│  │ qredin-agent│  │ qredin-agent│       │   │
│  │  │ App A       │  │ App B       │  │ App C       │       │   │
│  │  │ App D       │  │ App E       │  │             │       │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘         │   │
│  │        │                │                │                   │   │
│  │        └────────────────┼────────────────┘                   │   │
│  │                         ▼                                    │   │
│  │              ┌─────────────────────┐                         │   │
│  │              │  Workload API       │                         │   │
│  │              │  (Unix Socket)      │                         │   │
│  │              │  Apps get SVIDs     │                         │   │
│  │              └─────────────────────┘                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  YOUR LAPTOP:  qredin-operator  ──────►  Load Balancer ─────► Server │
│                  (Remote Control)       (TLS)          (Control Plane)│
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Where Each Binary Runs (Production)

### 1. `qredin-server` — The Brain
**Runs on: Dedicated Control Plane VMs (3+ for HA)**

| Spec | Recommendation |
|------|----------------|
| **Count** | 3 (1 primary + 2 replicas) |
| **VM Size** | 4 vCPU, 16 GB RAM, 100 GB SSD |
| **OS** | Ubuntu 22.04 LTS / RHEL 9 |
| **Network** | Private subnet, no public IP |
| **Ports** | 443 (gRPC), 9090 (health/metrics) |
| **Process Manager** | systemd (see below) |

**systemd service** (`/etc/systemd/system/qredin-server.service`):
```ini
[Unit]
Description=Qredin Identity Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=notify
User=qredin
Group=qredin
ExecStart=/usr/local/bin/qredin-server --config /etc/qredin/server.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/qredin /var/run/qredin /etc/qredin

[Install]
WantedBy=multi-user.target
```

**Enable & start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qredin-server
sudo systemctl status qredin-server
```

---

### 2. `qredin-agent` — The Local Guard
**Runs on: EVERY application VM / K8s node**

| Target | How to Deploy |
|--------|---------------|
| **VMs (bare metal / cloud)** | systemd service (like server) |
| **Kubernetes** | DaemonSet (1 per node) |
| **Container (Docker)** | Sidecar or init container |

#### Option A: systemd on VMs
```ini
# /etc/systemd/system/qredin-agent.service
[Unit]
Description=Qredin Node Agent
After=network.target
Wants=network-online.target

[Service]
Type=notify
User=qredin
Group=qredin
ExecStart=/usr/local/bin/qredin-agent --config /etc/qredin/agent.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**Agent config** (`/etc/qredin/agent.yaml`):
```yaml
environment: production
trust_domain: company.io
http:
  uds_path: "/var/run/qredin/workload-api.sock"
postgres:
  dsn: "postgres://qredin:password@db.internal:5432/qredin?sslmode=verify-full"
key_manager:
  type: disk
  dir: "/var/lib/qredin/keys"
agent:
  server_addr: "qredin-server.internal:443"
  node_id: "spiffe://company.io/node/$(hostname)"
  join_token_ttl: "5m"
  join_token_max_retries: 5
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qredin-agent
```

#### Option B: Kubernetes DaemonSet (Recommended for K8s)
```yaml
# qredin-agent-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: qredin-agent
  namespace: qredin-system
spec:
  selector:
    matchLabels:
      app: qredin-agent
  template:
    metadata:
      labels:
        app: qredin-agent
    spec:
      serviceAccountName: qredin-agent
      hostNetwork: true
      hostPID: true
      containers:
      - name: qredin-agent
        image: your-registry/qredin-agent:v1.0.0
        command: ["qredin-agent", "--config", "/etc/qredin/agent.yaml"]
        volumeMounts:
        - name: config
          mountPath: /etc/qredin
        - name: workload-socket
          mountPath: /var/run/qredin
        - name: keys
          mountPath: /var/lib/qredin/keys
        securityContext:
          privileged: true  # Needed for attestation
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: config
        configMap:
          name: qredin-agent-config
      - name: workload-socket
        hostPath:
          path: /var/run/qredin
          type: DirectoryOrCreate
      - name: keys
        hostPath:
          path: /var/lib/qredin/keys
          type: DirectoryOrCreate
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: qredin-agent-config
  namespace: qredin-system
data:
  agent.yaml: |
    environment: production
    trust_domain: company.io
    agent:
      server_addr: "qredin-server.qredin-system.svc:443"
      node_id: "spiffe://company.io/node/$(NODE_NAME)"
```

```bash
kubectl apply -f qredin-agent-daemonset.yaml
```

---

### 3. `qredin-operator` — The CLI
**Runs on: Your laptop / bastion host**

```bash
# Install on your laptop
go install github.com/qredin/qredin/cmd/qredin-operator@latest

# Or download release binary
curl -L https://github.com/qredin/qredin/releases/download/v1.0.0/qredin-operator-linux-amd64.tar.gz | tar xz
sudo mv qredin-operator /usr/local/bin/

# Configure (points to load balancer, not direct server)
cat > ~/.qredin/config.yaml <<EOF
server_addr: "qredin.company.io:443"
tls:
  cert_file: ~/.qredin/client.crt
  key_file: ~/.qredin/client.key
  ca_file: ~/.qredin/ca.crt
EOF

# Use it
qredin-operator --config ~/.qredin/config.yaml node list
qredin-operator --config ~/.qredin/config.yaml policy apply -f policy.yaml
```

---

## Infrastructure Checklist (What You Need to Provision)

### 1. Control Plane (3 VMs minimum)
```bash
# Example: AWS EC2
# 3x t3.xlarge (4 vCPU, 16 GB) in private subnets
# Security Group: Allow 443, 9090 from agent subnets only
# IAM Role: Allow access to Secrets Manager / KMS
```

### 2. PostgreSQL HA
```bash
# Option 1: AWS RDS PostgreSQL 16 (Multi-AZ)
# Option 2: Google Cloud SQL (HA)
# Option 3: Self-managed Patroni cluster (3 nodes)
# Required extensions: uuid-ossp, pgcrypto, btree_gin
```

### 3. Key Management (Choose One)
| Option | Use Case | Config |
|--------|----------|--------|
| **AWS KMS** | AWS native | `key_manager.type: aws_kms` |
| **HashiCorp Vault** | Multi-cloud, on-prem | `key_manager.type: vault` |
| **CloudHSM** | FIPS 140-2 Level 3 | `key_manager.type: aws_kms` + CloudHSM |
| **GCP Cloud KMS** | GCP native | `key_manager.type: gcp_kms` |

### 4. Load Balancer (for Server HA)
```yaml
# AWS ALB / NLB Target Group
# Targets: 3 server VMs on port 443
# Health Check: /healthz on port 9090
# TLS: Terminate at LB, re-encrypt to targets (or pass-through)
```

### 5. DNS
```dns
# Internal DNS (Route53 private zone / Cloud DNS)
qredin-server.internal.    A    10.0.1.10, 10.0.2.10, 10.0.3.10
qredin.company.io.         CNAME qredin-server.internal.  # For operator
```

---

## Network Diagram (Production)

```
┌─────────────────────────────────────────────────────────────────┐
│                      VPC (10.0.0.0/16)                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │  Public Subnet   │    │  Private Subnet  │                   │
│  │  (Bastion)       │    │  (Control Plane) │                   │
│  │                  │    │                  │                   │
│  │  Bastion Host    │───►│  qredin-server-1 │                   │
│  │  (SSH only)      │    │  qredin-server-2 │                   │
│  │                  │    │  qredin-server-3 │                   │
│  └────────┬─────────┘    │  PostgreSQL HA   │                   │
│           │              │  HSM/KMS         │                   │
│           │ SSH          └────────┬─────────┘                   │
│           │                       │ mTLS                         │
│           ▼                       ▼                              │
│  ┌─────────────────────────────────────────┐                    │
│  │          Private Subnets (Data Plane)    │                    │
│  │                                          │                    │
│  │  ┌──────────┐  ┌──────────┐  ┌────────┐ │                    │
│  │  │ App Tier │  │ App Tier │  │ DB Tier │  ...               │
│  │  │          │  │          │  │         │                     │
│  │  │ qredin-  │  │ qredin-  │  │ qredin- │                     │
│  │  │ agent    │  │ agent    │  │ agent   │                     │
│  │  └──────────┘  └──────────┘  └────────┘                     │
│  │       │            │            │                              │
│  │       └────────────┼────────────┘                              │
│  │                    ▼                                          │
│  │         ┌──────────────────┐                                  │
│  │         │  Workload API     │                                  │
│  │         │  (Unix Socket)    │                                  │
│  │         └──────────────────┘                                  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Deploy Commands (Summary)

### 1. Build Release Binaries
```bash
# On build machine
git clone https://github.com/qredin/qredin.git
cd qredin
git tag v1.0.0
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/qredin-server ./cmd/qredin-server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/qredin-agent ./cmd/qredin-agent
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/qredin-operator ./cmd/qredin-operator

# Package
tar -czf qredin-v1.0.0-linux-amd64.tar.gz -C dist .
```

### 2. Deploy Server (on each control plane VM)
```bash
# As root on each control plane VM
tar -xzf qredin-v1.0.0-linux-amd64.tar.gz
sudo mv qredin-* /usr/local/bin/
sudo mkdir -p /etc/qredin /var/lib/qredin /var/run/qredin
sudo useradd -r -s /bin/false qredin
sudo chown -R qredin:qredin /etc/qredin /var/lib/qredin /var/run/qredin
# Copy server.yaml to /etc/qredin/
# Copy systemd service file
sudo systemctl daemon-reload
sudo systemctl enable --now qredin-server
```

### 3. Deploy Agent (on each app VM / via DaemonSet)
```bash
# On each VM (or via DaemonSet)
# Same steps as server but with agent.yaml and qredin-agent.service
```

### 4. Verify Deployment
```bash
# From your laptop (with operator config)
qredin-operator --config ~/.qredin/config.yaml health
qredin-operator --config ~/.qredin/config.yaml node list
qredin-operator --config ~/.qredin/config.yaml policy apply -f policy.yaml
```

---

## Demo vs Production Quick Comparison

| | Demo | Production |
|---|------|------------|
| **Server** | 1 on laptop | 3 VMs (HA) + Load Balancer |
| **Agent** | 1 on laptop | 1 per VM / DaemonSet per K8s node |
| **DB** | Docker on laptop | RDS / Cloud SQL / Patroni HA |
| **Keys** | Disk (`/tmp`) | HSM / Cloud KMS / Vault |
| **Network** | localhost | VPC, Private Subnets, mTLS |
| **Access** | Direct | Load Balancer + Bastion |
| **Config** | `/tmp/...` | `/etc/qredin/` (systemd) |
| **Process** | Foreground | systemd / Kubernetes |

---

## The Key Insight

> **Demo = "It works on my machine"**
> 
> **Production = "It works on 100 machines, survives failures, rotates keys automatically, and I control it from my laptop."**

The **code is the same**. Only the **deployment topology** changes.

> **qredin-server** → 3 VMs behind LB → **qredin-agent** → 100 VMs/DaemonSet → **qredin-operator** → Your laptop