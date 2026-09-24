# Qredin Operations Runbook

## Overview

This runbook covers the standard operational procedures for Qredin production deployments.

## 1. Upgrade

1. Confirm current version: `qredin-operator --config /etc/qredin/server.yaml --version`
2. Confirm no pending policy rollouts: `qredin-operator --config /etc/qredin/server.yaml list-policies`
3. Apply database migrations: `qredin-operator --config /etc/qredin/server.yaml migrate --config /etc/qredin/server.yaml`
4. Roll out new binaries: `systemctl restart qredin-server qredin-authz`
5. Verify health: `curl -s http://localhost:9090/healthz`
6. Verify readiness: `curl -s http://localhost:9090/readyz`
7. Verify workload API: `curl -s --unix-socket /var/run/qredin/workload-api.sock http://localhost/workload.spiffe.io/v1/WorkloadAPI`

## 2. Rollback

1. Stop new deployments: `systemctl stop qredin-server qredin-authz`
2. Restore previous binary version
3. If migrations were applied, do not downgrade without a tested downgrade path
4. Restart services: `systemctl start qredin-server qredin-authz`
5. Verify health: `curl -s http://localhost:9090/healthz`

## 3. Migration

1. Take a database backup: `pg_dump -U qredin qredin > qredin.backup.sql`
2. Verify backup: `pg_restore -l qredin.backup.sql`
3. Apply migrations: `qredin-operator --config /etc/qredin/server.yaml migrate --config /etc/qredin/server.yaml`
4. Verify migration status: `qredin-operator --config /etc/qredin/server.yaml migrations`
5. Run smoke tests: `qredin-operator --config /etc/qredin/server.yaml smoke-test`

## 4. Key Rotation

1. Generate new CA key: `qredin-operator --config /etc/qredin/server.yaml rotate-key`
2. Verify new key is healthy: `qredin-operator --config /etc/qredin/server.yaml key-status`
3. Force workload credential refresh: `qredin-operator --config /etc/qredin/server.yaml refresh-workloads`
4. Monitor for new SVIDs: `qredin-operator --config /etc/qredin/server.yaml status`
5. Remove old key after all workloads refresh: `qredin-operator --config /etc/qredin/server.yaml remove-old-key`

## 5. Incident: Server Down

1. Check service status: `systemctl status qredin-server`
2. Check logs: `journalctl -u qredin-server -n 100`
3. Check database connectivity: `psql -U qredin -d qredin -c 'SELECT 1'`
4. Check disk space: `df -h`
5. Restart if service is stuck: `systemctl restart qredin-server`
6. If database is the issue, escalate to DBA and follow recovery procedures

## 6. Incident: Agent Cannot Authenticate

1. Check server health: `curl -s http://localhost:9090/healthz`
2. Check join token store: `qredin-operator --config /etc/qredin/server.yaml tokens`
3. Check agent logs: `journalctl -u qredin-agent -n 100`
4. Verify node ID is registered: `qredin-operator --config /etc/qredin/server.yaml list-registrations`
5. If registration is revoked, restore via approval workflow: `qredin-operator --config /etc/qredin/server.yaml approve-registration`

## 7. Backup and Recovery

### Recovery Point Objective (RPO)
- Target: 24 hours
- Definition: Maximum acceptable amount of data loss measured in time
- Measurement: Time since last successful backup
- Alert: Trigger if RPO exceeds 24 hours
- Test: Verify backup creation updates LastBackupTime

### Recovery Time Objective (RTO)
- Target: 1 hour
- Definition: Maximum acceptable time to restore service after failure
- Measurement: Duration of last restore operation
- Alert: Trigger if RTO exceeds 1 hour
- Test: Verify restore completion updates RestoreDuration

### Backup Verification
1. List backups: `qredin-operator --config /etc/qredin/server.yaml list-backups`
2. Verify backup integrity: `qredin-operator --config /etc/qredin/server.yaml verify-backup <backup-id>`
3. Test restore procedure: `qredin-operator --config /etc/qredin/server.yaml test-restore --backup-id <backup-id> --target-db <connection-string>`

### Retention Policy
- Daily backups retained for 7 days
- Weekly backups retained for 4 weeks
- Monthly backups retained for 12 months
- Automatic cleanup via `CleanupBackups` function
