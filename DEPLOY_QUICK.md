# Qredin Deployment — The "Vercel/Railway/Supabase" Equivalent

---

## The One-Liner

| Component | Where It Runs | The "Provider" Equivalent |
|-----------|---------------|---------------------------|
| **qredin-server** | 3 VMs behind a Load Balancer | **Railway/Render** (your backend) |
| **qredin-agent** | Every app VM / K8s node | **Vercel Edge** (runs everywhere your app runs) |
| **qredin-operator** | Your laptop | **Your laptop** (CLI only) |
| **PostgreSQL** | Managed DB (RDS/CloudSQL) | **Supabase/Neon/PlanetScale** |
| **Keys (HSM)** | AWS KMS / Vault / CloudHSM | **Vercel Env Vars / Doppler / Infisical** |

---

## The 3 Things You Actually Deploy

### 1. PostgreSQL → Supabase/Neon/RDS (Managed)
```bash
# Option 1: Supabase (easiest)
# Create project at supabase.com → get connection string
# DSN: "postgres://postgres:password@db.xxx.supabase.co:5432/postgres?sslmode=require"

# Option 2: Neon (serverless)
# neon.tech → connection string
# DSN: "postgres://user:pass@ep-xxx.us-east-1.aws.neon.tech/qredin?sslmode=require"

# Option 3: AWS RDS / Google Cloud SQL
# Standard managed PostgreSQL 15+
```

**That's it. No self-hosted PostgreSQL.**

---

### 2. qredin-server → 3 VMs + Load Balancer (Your "Backend")

**Where:** 3 Linux VMs (any cloud: AWS EC2, GCP Compute, DigitalOcean, Hetzner)

**Specs per VM:**
- 4 vCPU, 16 GB RAM, 100 GB SSD
- Ubuntu 22.04 LTS
- Private network only (no public IP)

**Infrastructure:**
```
Internet
    │
    ▼
┌─────────────────┐
│  Load Balancer  │  ← AWS ALB / GCP Cloud LB / Cloudflare Tunnel / Tailscale Funnel
│  (Port 443)     │     Terminate TLS here, forward to :443 on VMs
└────────┬────────┘
         │
    ┌────┴────┬────────┐
    ▼         ▼        ▼
┌────────┐ ┌────────┐ ┌────────┐
│ VM 1    │ │ VM 2   │ │ VM 3   │  ← 3 VMs for HA
│ qredin- │ │ qredin-│ │ qredin-│
│ server  │ │ server │ │ server │
└────────┘ └────────┘ └────────┘
         │         │         │
         └─────────┼─────────┘
                   ▼
            ┌─────────────┐
            │ PostgreSQL  │  ← Supabase/Neon/RDS (managed)
            └─────────────┘
```

**On each VM (run as root once):**
```bash
# 1. Install binary
curl -L https://github.com/qredin/qredin/releases/download/v1.0.0/qredin-server-linux-amd64 -o /usr/local/bin/qredin-server
chmod +x /usr/local/bin/qredin-server

# 2. Create user & dirs
useradd -r -s /bin/false qredin
mkdir -p /etc/qredin /var/lib/qredin /var/run/qredin
chown -R qredin:qredin /etc/qredin /var/lib/qredin /var/run/qredin

# 2. Config at /etc/qredin/server.yaml
cat > /etc/qredin/server.yaml <<EOF
environment: production
log_level: info
log_format: json
trust_domain: yourcompany.io

http:
  listen_addr: ":443"
  uds_path: "/var/run/qredin/workload-api.sock"
  tls_cert: "/etc/qredin/tls/server.crt"
  tls_key: "/etc/qredin/tls/server.key"

postgres:
  dsn: "postgres://user:pass@db.supabase.co:5432/postgres?sslmode=require"
  max_conns: 25
  min_conns: 5

key_manager:
  type: aws_kms
  region: us-east-1
  key_id: "arn:aws:kms:us-east-1:123456789:key/xxx"

operator:
  rate_limit:
    enabled: true
    requests: 1000
    window: "1m"
EOF

# 3. TLS certs (from Let's Encrypt / your CA)
mkdir -p /etc/qredin/tls
# Place server.crt and server.key here

# 4. systemd service
cat > /etc/systemd/system/qredin-server.service <<'EOF'
[Unit]
Description=Qredin Identity Server
After=network.target
[Service]
Type=notify
User=qredin
Group=qredin
ExecStart=/usr/local/bin/qredin-server --config /etc/qredin/server.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# 5. Start
systemctl daemon-reload
systemctl enable --now qredin-server
systemctl status qredin-server
```

**Do this on 3 VMs. Put a Load Balancer in front. Done.**

---

### 3. qredin-agent → Every App Machine (Like Vercel Edge)

**Where:** Every VM, K8s node, or container host that runs your apps.

**Option A: Linux VMs (systemd)**
```bash
# On EVERY app VM (same steps as server but agent config)
curl -L https://github.com/qredin/qredin/releases/download/v1.0.0/qredin-agent-linux-amd64 -o /usr/local/bin/qredin-agent
chmod +x /usr/local/bin/qredin-agent

useradd -r -s /bin/false qredin
mkdir -p /etc/qredin /var/lib/qredin /var/run/qredin
chown -R qredin:qredin /etc/qredin /var/lib/qredin /var/run/qredin

cat > /etc/qredin/agent.yaml <<EOF
environment: production
trust_domain: yourcompany.io

agent:
  server_addr: "lb.yourcompany.io:443"  # ← Load Balancer DNS!
  node_id: "spiffe://yourcompany.io/node/$(hostname)"
  join_token_ttl: "5m"
  join_token_max_retries: 5

key_manager:
  type: disk
  dir: "/var/lib/qredin/keys"
EOF

# systemd service (same pattern)
systemctl daemon-reload
systemctl enable --now qredin-agent
```

**That's it. Run this on every VM. The agent connects to the Load Balancer.**

---

**Option B: Kubernetes (DaemonSet — 1 command)**
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
        image: ghcr.io/qredin/qredin-agent:v1.0.0
        command: ["qredin-agent", "--config", "/etc/qredin/agent.yaml"]
        volumeMounts:
        - name: config
          mountPath: /etc/qredin
        - name: workload-socket
          mountPath: /var/run/qredin
        - name: keys
          mountPath: /var/lib/qredin/keys
        securityContext:
          privileged: true
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
    trust_domain: yourcompany.io
    agent:
      server_addr: "qredin-server.yourcompany.io:443"
      node_id: "spiffe://yourcompany.io/node/$(NODE_NAME)"
```

```bash
kubectl apply -f qredin-agent-daemonset.yaml
# Done. 1 agent per node, auto-scaling with cluster.
```

---

### 4. qredin-operator → Your Laptop (CLI Only)

```bash
# On YOUR laptop only
go install github.com/qredin/qredin/cmd/qredin-operator@latest

# Config at ~/.qredin/config.yaml
mkdir -p ~/.qredin
cat > ~/.qredin/config.yaml <<EOF
server_addr: "https://api.yourcompany.io"  # Your Load Balancer / API Gateway
tls:
  cert_file: ~/.qredin/client.crt
  key_file: ~/.qredin/client.key
  ca_file: ~/.qredin/ca.crt
EOF

# Use it
qredin-operator --config ~/.qredin/config.yaml node list
qredin-operator --config ~/.qredin/config.yaml policy apply -f policy.yaml
```

**That's it. CLI only runs on your laptop.**

---

## The DNS/Network Setup (One-Time)

| Record | Value | Purpose |
|--------|-------|---------|
| `qredin.yourcompany.io` | ALB/Cloud LB IP | Server gRPC endpoint |
| `api.yourcompany.io` | ALB/Cloud LB IP | Operator CLI endpoint |
| `*.qredin.yourcompany.io` | (internal) | Internal service discovery |

**Load Balancer Config:**
- **Listener:** 443 (HTTPS/TLS)
- **Target Group:** 3 server VMs on port 443
- **Health Check:** `GET /healthz` on port 9090
- **TLS:** Terminate at LB, re-encrypt to VMs (or passthrough)

---

## The 3 Files You Actually Edit

| File | Where | Purpose |
|------|-------|---------|
| `/etc/qredin/server.yaml` | 3 server VMs | Brain config |
| `/etc/qredin/agent.yaml` | Every app VM / ConfigMap | Guard config |
| `~/.qredin/config.yaml` | Your laptop | CLI config |

**That's it. 3 config files.**

---

## The "Railway/Vercel/Supabase" Summary

| Qredin Piece | Deploy Like | Where |
|--------------|-------------|-------|
| **qredin-server** | Railway/Render (3 instances + LB) | 3 VMs + Load Balancer |
| **qredin-agent** | Vercel Edge (every node) | Every VM / K8s DaemonSet |
| **qredin-operator** | Your laptop (CLI) | Your laptop |
| **PostgreSQL** | Supabase/Neon/RDS | Managed DB |
| **Keys/HSM** | Doppler/Infisical/Vault | AWS KMS / Vault / CloudHSM |

---

## One-Command Deploy (If You Have Terraform)

```hcl
# terraform/main.tf (simplified)
module "qredin_server" {
  source  = "your-org/qredin-server/aws"
  count   = 3
  instance_type = "t3.xlarge"
  subnet_ids    = var.private_subnets
  db_dsn        = var.supabase_dsn
  kms_key_arn   = aws_kms_key.qredin.arn
}

resource "aws_lb" "qredin" {
  internal           = true
  security_groups    = [aws_sg.lb.id]
  subnets            = var.private_subnets
}

resource "aws_lb_target_group" "qredin" {
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id
  health_check {
    path                = "/healthz"
    port                = "9090"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "qredin" {
  load_balancer_arn = aws_lb.qredin.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.qredin.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qredin.arn
  }
}
```

```bash
terraform apply
# Deploys 3 server VMs, Load Balancer, health checks, TLS
# Then: deploy agent DaemonSet to K8s, or systemd on VMs
```

---

## TL;DR — Your Deploy Checklist

```
[ ] 1. Create Supabase/Neon project → get DSN
[ ] 2. Provision 3 VMs (t3.xlarge, Ubuntu 22.04, private subnet)
[ ] 2b. Create AWS KMS key / Vault cluster for keys
[ ] 3. Put Load Balancer in front of 3 VMs (port 443)
[ ] 4. On each VM: install qredin-server, systemd, start
[ ] 5. On each app VM/K8s: deploy qredin-agent (DaemonSet or systemd)
[ ] 6. On laptop: install qredin-operator, configure LB endpoint
[ ] 7. Point DNS to Load Balancer
[ ] 8. Run: qredin-operator policy apply -f your-policy.yaml
```

**That's your production deployment. No more "demo on one laptop."**