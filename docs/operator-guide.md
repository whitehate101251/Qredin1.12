# Qredin Operator Guide

## Installation

### System Requirements

- Go 1.23+ for builds
- PostgreSQL 16+ for database
- Linux kernel 5.15+ (for UDS peer credentials)

### Quick Start (Docker Compose)

```bash
cd deploy/compose
docker compose up -d
```

### Production (Kubernetes)

```bash
kubectl apply -f deploy/k8s/
```

### Production (VM / Bare-metal)

```bash
# Install binaries
cp bin/qredin-server /usr/local/bin/
cp bin/qredin-agent /usr/local/bin/
cp bin/qredin-authz /usr/local/bin/
cp bin/qredin-operator /usr/local/bin/

# Create user
useradd -r -s /sbin/nologin qredin

# Install configs
mkdir -p /etc/qredin
cp deploy/config/server.prod.yaml /etc/qredin/server.yaml
cp deploy/config/agent.prod.yaml /etc/qredin/agent.yaml
cp deploy/config/authz.prod.yaml /etc/qredin/authz.yaml
chown -R qredin:qredin /etc/qredin

# Install systemd units
cp deploy/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable qredin-server qredin-agent qredin-authz
systemctl start qredin-server qredin-authz
systemctl start qredin-agent
```

## Configuration

All services use YAML configuration. See `docs/BUILD.md` for schema.

### Key Manager

```yaml
key_manager:
  type: aws_kms
  region: us-east-1
  key_id: arn:aws:kms:us-east-1:123456789012:key/abcd-efgh
```

### TLS

```yaml
http:
  listen_addr: ":443"
  uds_path: "/var/run/qredin/workload-api.sock"
  tls_cert: "/etc/qredin/tls/server.crt"
  tls_key: "/etc/qredin/tls/server.key"
```

## Common Operations

### List Registrations

```bash
qredin-operator --config /etc/qredin/server.yaml list-registrations
```

### Approve Registration

```bash
qredin-operator --config /etc/qredin/server.yaml approve-registration <registration-id>
```

### List Policies

```bash
qredin-operator --config /etc/qredin/server.yaml list-policies
```

### Apply Migrations

```bash
qredin-operator --config /etc/qredin/server.yaml migrate
```

### Key Rotation

```bash
qredin-operator --config /etc/qredin/server.yaml rotate-key
```

### Audit Query

```bash
qredin-operator --config /etc/qredin/server.yaml audit --start 2024-01-01 --end 2024-12-31
```

## Monitoring

```bash
# Health
curl -s http://localhost:9090/healthz

# Readiness
curl -s http://localhost:9090/readyz

# Metrics
curl -s http://localhost:9090/metrics
```

## Troubleshooting

| Symptom | Check | Resolution |
|---|---|---|
| Agent cannot connect | `journalctl -u qredin-agent` | Verify server health, join token, node ID |
| SVID not issued | `curl /readyz` | Check CA key, database, policy |
| Policy denied | `curl /metrics` | Check policy cache, audit log |
| Migration failed | `qredin-operator migrate --dry-run` | Restore from backup, reapply |

## Security Hardening

- Run all services as non-root `qredin` user
- Set file permissions to minimum required
- Use AWS KMS for CA keys in production
- Enable TLS for all gRPC endpoints
- Restrict database access to service CIDR
- Rotate CA keys quarterly
- Review audit logs weekly