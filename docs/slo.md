# Qredin Service Level Objectives and Alerting

## Overview

This document defines the Service Level Objectives (SLOs) for Qredin Identity and Authorization Platform, the corresponding alerting rules, and on-call procedures.

## Service Level Indicators (SLIs)

| SLI | Description | Measurement |
|-----|-------------|-------------|
| **Availability** | Fraction of successful Workload API requests | Successful requests / Total requests over 5m window |
| **Latency (p99)** | 99th percentile Workload API response time | Histogram of gRPC unary call duration |
| **Latency (p99.9)** | 99.9th percentile Workload API response time | Histogram of gRPC unary call duration |
| **SVID Issuance Latency** | Time from request to SVID delivery | Histogram of X509SVID issuance duration |
| **Bundle Freshness** | Time since last bundle update | Time since bundle source last updated |
| **Authorization Decision Latency** | Time for authz decision | Histogram of policy evaluation duration |

## Service Level Objectives (SLOs)

### Critical Path (Workload API)

| Metric | Target | Window | Burn Rate Alert |
|--------|--------|--------|-----------------|
| Availability | 99.95% | 30 days | 2% error budget burn in 1h |
| Latency p99 | < 50ms | 5 minutes | Sustained > 100ms for 5m |
| Latency p99.9 | < 200ms | 5 minutes | Sustained > 500ms for 5m |

### Authorization API

| Metric | Target | Window | Burn Rate Alert |
|--------|--------|--------|-----------------|
| Availability | 99.9% | 30 days | 2% error budget burn in 1h |
| Decision Latency p99 | < 10ms | 5 minutes | Sustained > 50ms for 5m |

### Database

| Metric | Target | Window | Burn Rate Alert |
|--------|--------|--------|-----------------|
| Connection Pool Utilization | < 80% | 5 minutes | > 90% for 2m |
| Query Latency p99 | < 100ms | 5 minutes | > 500ms for 5m |
| Migration Success Rate | 100% | Per migration | Any failure |

### Backup & Recovery

| Metric | Target | Window | Alert |
|--------|--------|--------|-------|
| Backup Success Rate | 100% | Daily | Any failure |
| RPO | < 24 hours | Continuous | RPO > 24h |
| RTO | < 1 hour | Per restore | RTO > 1h |

### Certificate Authority

| Metric | Target | Window | Alert |
|--------|--------|--------|-------|
| SVID Issuance Success | 99.99% | 1 hour | Any failure |
| Authority Rotation Success | 100% | Per rotation | Any failure |
| SVID Expiry Warning | > 72h before expiry | Continuous | < 24h remaining |

## Alerting Rules

### Critical Alerts (Page Immediately)

```yaml
groups:
- name: qredin-critical
  interval: 30s
  rules:
  # Workload API unavailable
  - alert: QredinWorkloadAPIDown
    expr: |
      sum(rate(qredin_workloadapi_requests_total{status=~"5.."}[5m])) 
      / sum(rate(qredin_workloadapi_requests_total[5m])) > 0.05
    for: 2m
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "Workload API error rate > 5%"
      description: "Error rate is {{ $value | humanizePercentage }} for 2 minutes"
      runbook: "https://runbooks.example.com/qredin-workload-api-down"

  # Database unavailable
  - alert: QredinDatabaseDown
    expr: |
      qredin_db_health_check_status == 0
    for: 1m
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "Database health check failing"
      runbook: "https://runbooks.example.com/qredin-database-down"

  # Backup failure
  - alert: QredinBackupFailed
    expr: |
      qredin_backup_last_success_timestamp < time() - 86400
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "No successful backup in 24 hours"
      runbook: "https://runbooks.example.com/qredin-backup-failed"

  # RPO exceeded
  - alert: QredinRPOExceeded
    expr: |
      time() - qredin_backup_last_success_timestamp > 86400
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "RPO exceeded 24 hours"
      runbook: "https://runbooks.example.com/qredin-rpo-exceeded"

  # Authority rotation failure
  - alert: QredinAuthorityRotationFailed
    expr: |
      qredin_ca_rotation_status{status="failed"} == 1
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "CA authority rotation failed"
      runbook: "https://runbooks.example.com/qredin-authority-rotation-failed"

  # SVID expiry imminent
  - alert: QredinSVIDExpiryImminent
    expr: |
      qredin_svid_min_expiry_seconds < 86400
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "SVID expires in < 24 hours"
      runbook: "https://runbooks.example.com/qredin-svid-expiry-imminent"
```

### Warning Alerts (Notify During Business Hours)

```yaml
- name: qredin-warning
  interval: 5m
  rules:
  # High latency
  - alert: QredinHighLatency
    expr: |
      histogram_quantile(0.99, qredin_workloadapi_request_duration_seconds_bucket) > 0.1
    for: 5m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Workload API p99 latency > 100ms"

  # Database connection pool exhaustion
  - alert: QredinDBPoolExhaustion
    expr: |
      qredin_db_pool_utilization > 0.85
    for: 5m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Database connection pool > 85% utilized"

  # Certificate expiry warning
  - alert: QredinCertificateExpiryWarning
    expr: |
      qredin_cert_expiry_seconds < 604800
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Certificate expires in < 7 days"

  # Audit log lag
  - alert: QredinAuditLogLag
    expr: |
      qredin_audit_log_lag_seconds > 300
    for: 5m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Audit log lag > 5 minutes"
```

## On-Call Procedures

### Escalation Policy

| Tier | Response Time | Escalation |
|------|---------------|------------|
| **L1 (Primary)** | 15 minutes | Auto-escalate to L2 after 15m |
| **L2 (Secondary)** | 30 minutes | Auto-escalate to L3 after 30m |
| **L3 (Manager)** | 1 hour | Page CTO after 1h |

### Runbook Links

| Alert | Runbook |
|-------|---------|
| WorkloadAPIDown | `ops/runbooks/workload-api-down.md` |
| DatabaseDown | `ops/runbooks/database-down.md` |
| BackupFailed | `ops/runbooks/backup-failed.md` |
| RPOExceeded | `ops/runbooks/rpo-exceeded.md` |
| AuthorityRotationFailed | `ops/runbooks/authority-rotation-failed.md` |
| SVIDExpiryImminent | `ops/runbooks/svid-expiry-imminent.md` |
| HighLatency | `ops/runbooks/high-latency.md` |
| DBPoolExhaustion | `ops/runbooks/db-pool-exhaustion.md` |
| CertificateExpiryWarning | `ops/runbooks/cert-expiry-warning.md` |

### L1 Response Checklist

1. **Acknowledge alert** within 5 minutes
2. **Check dashboard**: `https://grafana.example.com/d/qredin/overview`
3. **Identify scope**: Single instance? All instances? Specific trust domain?
4. **Check recent deployments**: `kubectl rollout history deployment/qredin-server`
5. **Check logs**: `kubectl logs -l app=qredin-server --tail=100`
6. **Apply mitigation** per runbook
7. **Update incident** in PagerDuty/incident tracker
8. **Escalate if needed** per escalation policy

### Post-Incident Process

1. **Incident review** within 48 hours
2. **Root cause analysis** documented
3. **Action items** tracked in Jira/Linear
4. **Runbook updates** if gaps found
5. **SLO impact** calculated and reported

## SLO Reporting

### Monthly SLO Report Template

```markdown
# Qredin SLO Report - {{ month }}

## Summary
- **Overall Availability**: {{ availability }}% (Target: 99.95%)
- **Error Budget Remaining**: {{ budget }}%
- **Incidents**: {{ count }} ({{ sev0 }} SEV-0, {{ sev1 }} SEV-1)

## SLI Details
| SLI | Actual | Target | Status |
|-----|--------|--------|--------|
| Workload API Availability | {{ api_avail }}% | 99.95% | {{ api_status }} |
| Workload API p99 Latency | {{ api_p99 }}ms | < 50ms | {{ latency_status }} |
| Authz API Availability | {{ authz_avail }}% | 99.9% | {{ authz_status }} |
| Backup Success Rate | {{ backup_success }}% | 100% | {{ backup_status }} |
| RPO | {{ rpo_hours }}h | < 24h | {{ rpo_status }} |
| RTO | {{ rto_minutes }}m | < 60m | {{ rto_status }} |

## Top Incidents
1. {{ incident_1 }}
2. {{ incident_2 }}

## Action Items
- [ ] {{ action_1 }}
- [ ] {{ action_2 }}
```