# Qredin Support Matrix

## Deployment Types

| Platform | Kubernetes | VM / Bare-metal | Docker Compose |
|---|---|---|---|
| x509svid | ✅ | ✅ | ✅ |
| KeyManager (Disk) | ✅ | ✅ | ✅ |
| KeyManager (AWS KMS) | ✅ | ❌ | ❌ |
| Node Attestation | ✅ | ✅ | ✅ |
| Workload API | ✅ | ✅ | ✅ |

## Attestation Targets

| Platform | Unix | Docker | systemd | Kubernetes |
|---|---|---|---|---|
| x509svid | ✅ | ✅ | ✅ | ✅ |

## Authentication Methods

| Protocol | Available | FIPS | mTLS |
|---|---|---|---|
| gRPC | ✅ | ✅ | ✅ |
| Workload API | ✅ | ✅ | ✅ |

## File Permissions

- CA key files: `0o600`
- Workload API UDS: `0o600`
- Qredin config: `0o640` (owner group qredin)
- Registration data: `0o640` (owner group qredin)

## Monitoring

- Health: `/healthz` HTTP endpoint
- Readiness: `/readyz` HTTP endpoint
- Metrics: `/metrics` Prometheus endpoint
- Structured logs via `log/slog`
- Audit correlation IDs

## Backup / Recovery

- Database: `pg_dump` / `pg_restore`
- Audit events: Append-only; immutable
- SVIDs: Reissued on server restart; CA rotation involves new signing
- Join tokens: Rotated via token store