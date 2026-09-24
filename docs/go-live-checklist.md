# Qredin Go-Live Checklist

## Pre-Deployment Requirements

### Security Review
- [ ] External security audit completed
- [ ] All critical/high vulnerabilities resolved
- [ ] Penetration test report reviewed
- [ ] Threat model validated
- [ ] Risk register updated with accepted risks
- [ ] Incident response plan tested

### Compliance
- [ ] Data protection impact assessment (DPIA) complete
- [ ] Regulatory requirements mapped (GDPR, SOC2, etc.)
- [ ] Audit logging requirements verified
- [ ] Data retention policies configured
- [ ] Encryption at rest/in transit verified

### Documentation
- [ ] Architecture decision records (ADRs) reviewed
- [ ] Runbooks published and accessible
- [ ] API documentation published
- [ ] Operational procedures documented
- [ ] Disaster recovery plan documented
- [ ] On-call rotation schedule published

## Infrastructure Readiness

### Database
- [ ] PostgreSQL 15/16 provisioned
- [ ] Required extensions installed (uuid-ossp, pgcrypto, btree_gin)
- [ ] Connection pooler configured (PgBouncer)
- [ ] Read replicas configured for HA
- [ ] Backup schedule configured (daily, point-in-time recovery)
- [ ] Backup retention policy set (7 daily, 4 weekly, 12 monthly)
- [ ] Backup encryption verified
- [ ] Restore procedure tested and documented
- [ ] RPO < 24h, RTO < 1h validated

### Kubernetes / Compute
- [ ] Cluster version 1.27+ provisioned
- [ ] Node pools sized for workload (min 3 control plane, 3+ workers)
- [ ] Resource quotas/limits configured
- [ ] Network policies configured
- [ ] Pod security standards enforced (restricted)
- [ ] CSI driver for persistent volumes
- [ ] Ingress controller deployed (Envoy/NGINX)
- [ ] Service mesh deployed (Istio/Linkerd/Cilium) if required

### Networking
- [ ] VPC/VNet configured with private subnets
- [ ] Load balancers provisioned (internal/external)
- [ ] DNS zones configured (internal/external)
- [ ] TLS certificates provisioned (valid > 90 days)
- [ ] mTLS enforced for all service-to-service
- [ ] Firewall rules least-privilege
- [ ] Egress controls for external dependencies

### Secrets Management
- [ ] Vault/KMS/CloudHSM provisioned
- [ ] CA root keys stored in HSM
- [ ] Database credentials in secrets manager
- [ ] API keys/tokens in secrets manager
- [ ] Certificate private keys in HSM
- [ ] Rotation policies configured
- [ ] Access policies least-privilege
- [ ] Audit logging enabled

### Monitoring & Alerting
- [ ] Prometheus/Grafana deployed
- [ ] SLO dashboards configured
- [ ] Critical alerts configured (pages)
- [ ] Warning alerts configured (tickets)
- [ ] Log aggregation deployed (Loki/Elastic)
- [ ] Distributed tracing deployed (Jaeger/Tempo)
- [ ] Synthetic monitoring for critical paths
- [ ] Runbook links in alert annotations

## Application Deployment

### Identity Server
- [ ] Configuration validated (`qredin-operator --config validate`)
- [ ] Trust domain configured
- [ ] Authority TTL set (recommend 24h)
- [ ] Key manager connected (HSM/KMS)
- [ ] Health/readiness endpoints responding
- [ ] Metrics endpoint exposed
- [ ] UDS socket permissions correct (0700, qredin:qredin)
- [ ] Admin gRPC listener TLS configured
- [ ] Workload API UDS listener configured

### Node Agent
- [ ] Configuration validated
- [ ] Server address reachable
- [ ] Node ID unique per node
- [ ] Join token TTL configured (recommend 5m)
- [ ] Join token max retries configured (recommend 5)
- [ ] Attestation plugins installed (k8s, docker, systemd)
- [ ] Reconnect backoff configured (1s base, 60s max)
- [ ] Health/readiness endpoints responding

### Authorization Service
- [ ] Policy repository initialized
- [ ] Default deny policy active
- [ ] RBAC roles configured (admin, operator, auditor)
- [ ] Risk providers configured
- [ ] Decision cache sized appropriately
- [ ] Audit logging enabled

### Operator CLI
- [ ] Binary installed on bastion/ops hosts
- [ ] Config file permissions 0600
- [ ] Tab completion installed
- [ ] Version matches server/agent

## Data Migration

- [ ] Migration scripts reviewed and tested
- [ ] Schema version baseline established
- [ ] Migration rollback procedures tested
- [ ] Data integrity checks pass
- [ ] Migration window scheduled
- [ ] Rollback plan communicated

## Security Hardening

### Server Hardening
- [ ] Non-root user for all processes
- [ ] Read-only root filesystem
- [ ] Dropped capabilities (no CAP_SYS_ADMIN, etc.)
- [ ] Seccomp profile applied
- [ ] AppArmor/SELinux profile enforced
- [ ] File permissions least privilege (config 0600, keys 0400)

### Network Hardening
- [ ] Default deny network policies
- [ ] Egress allowlist for external APIs
- [ ] Ingress restricted to required ports
- [ ] Pod-to-pod encryption (mTLS)
- [ ] Service mesh sidecars injected

### Certificate Management
- [ ] Root CA offline/air-gapped
- [ ] Intermediate CA online for rotation
- [ ] SVID TTL ≤ 24 hours
- [ ] Bundle rotation automated
- [ ] Revocation propagation tested (< 5 min)

## Operational Validation

### Smoke Tests
- [ ] Server starts without errors
- [ ] Agent connects to server
- [ ] Workload API responds to valid requests
- [ ] Workload API rejects invalid requests
- [ ] SVID issued for test workload
- [ ] SVID verified by peer
- [ ] Bundle rotation works
- [ ] Authorization decisions returned
- [ ] Audit events recorded

### Integration Tests
- [ ] Cross-trust-domain federation works
- [ ] Policy allow/deny enforced
- [ ] Selector-based attestation works
- [ ] Join token flow works
- [ ] Approval workflow works
- [ ] Revocation propagation works (< 5 min)
- [ ] Key rotation works
- [ ] Backup/restore works

### Chaos Engineering
- [ ] DB primary failover tested
- [ ] Server restart doesn't drop connections
- [ ] Network partition handled gracefully
- [ ] Clock skew tolerance validated
- [ ] Reconnect storm handled
- [ ] Resource exhaustion handled

## Capacity Planning

### Resource Requirements
| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| Identity Server | 2 cores | 4 GB | 10 GB | 1 Gbps |
| Node Agent | 500m | 512 MB | 1 GB | 100 Mbps |
| Authz Service | 1 core | 2 GB | 5 GB | 1 Gbps |
| PostgreSQL | 4 cores | 16 GB | 100 GB+ | 10 Gbps |
| Vault/HSM | 2 cores | 4 GB | 10 GB | 1 Gbps |

### Scaling Triggers
- [ ] CPU > 70% for 5m → scale out
- [ ] Memory > 80% for 5m → scale out
- [ ] DB connections > 80% → scale pool
- [ ] Request latency p99 > 100ms → scale out
- [ ] Error rate > 1% → investigate

## Rollback Plan

### Triggers for Rollback
- [ ] Critical functionality broken
- [ ] Security vulnerability introduced
- [ ] Performance regression > 2x
- [ ] Data corruption detected

### Rollback Procedure
1. [ ] Stop new traffic to affected version
2. [ ] Drain connections gracefully (30s)
3. [ ] Revert deployment (`kubectl rollout undo`)
4. [ ] Verify health checks pass
5. [ ] Restore database if migration applied
6. [ ] Verify data integrity
7. [ ] Communicate rollback to stakeholders
8. [ ] Document root cause

## Go/No-Go Decision

### Final Gate (T-0)
| Criteria | Status | Owner |
|----------|--------|-------|
| All pre-deployment checks passed | ☐ | Release Manager |
| Infrastructure validated | ☐ | Platform Team |
| Security review signed off | ☐ | Security Team |
| Compliance sign-off | ☐ | Compliance Team |
| Runbooks accessible | ☐ | SRE Team |
| On-call rotation confirmed | ☐ | SRE Lead |
| Stakeholders notified | ☐ | PM |

### Go Decision
- [ ] **GO** - All criteria met, proceed with deployment
- [ ] **NO-GO** - Blockers exist, do not deploy
- [ ] **CONDITIONAL GO** - Minor issues with mitigation plan

---

**Sign-off:**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Release Manager | | | |
| Platform Lead | | | |
| Security Lead | | | |
| SRE Lead | | | |
| Engineering Director | | | |

---

*Checklist Version: 1.0*
*Last Updated: 2024-01-15*
*Classification: Internal - Confidential*