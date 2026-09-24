#!/bin/bash
# Qredin Backup Restore Test Script
# This script tests the backup and restore procedures for Qredin

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/lib/qredin/backups}"
DB_DSN="${DB_DSN:-postgres://qredin:password@localhost:5432/qredin?sslmode=disable}"
RESTORE_DB_DSN="${RESTORE_DB_DSN:-postgres://qredin:password@localhost:5433/qredin_restore?sslmode=disable}"
PASSPHRASE="${BACKUP_PASSPHRASE:-test-passphrase}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test 1: Create a backup
test_create_backup() {
    log_info "Test 1: Creating backup..."
    
    # Use qredin-operator to create backup
    if qredin-operator --config /etc/qredin/server.yaml create-backup; then
        log_info "Backup created successfully"
        return 0
    else
        log_error "Backup creation failed"
        return 1
    fi
}

# Test 2: Verify backup integrity
test_verify_backup() {
    log_info "Test 2: Verifying backup integrity..."
    
    # Find latest backup
    LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/backup_*.enc 2>/dev/null | head -1)
    
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_error "No backup files found"
        return 1
    fi
    
    log_info "Verifying backup: $LATEST_BACKUP"
    
    # Use qredin-operator to verify
    if qredin-operator --config /etc/qredin/server.yaml verify-backup "$LATEST_BACKUP"; then
        log_info "Backup verification successful"
        return 0
    else
        log_error "Backup verification failed"
        return 1
    fi
}

# Test 3: Restore backup to test database
test_restore_backup() {
    log_info "Test 3: Restoring backup to test database..."
    
    LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/backup_*.enc 2>/dev/null | head -1)
    
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_error "No backup files found"
        return 1
    fi
    
    # Restore to test database
    if qredin-operator --config /etc/qredin/server.yaml restore-backup \
        --backup-file "$LATEST_BACKUP" \
        --target-dsn "$RESTORE_DB_DSN" \
        --passphrase "$PASSPHRASE"; then
        log_info "Backup restore successful"
        return 0
    else
        log_error "Backup restore failed"
        return 1
    fi
}

# Test 4: Verify restored data integrity
test_verify_restored_data() {
    log_info "Test 4: Verifying restored data integrity..."
    
    # Check that key tables exist and have data
    TABLES=("qredin_trust_domains" "qredin_registrations" "qredin_authorities" "qredin_audit_events")
    
    for TABLE in "${TABLES[@]}"; do
        COUNT=$(psql "$RESTORE_DB_DSN" -t -c "SELECT count(*) FROM $TABLE;" 2>/dev/null | xargs)
        if [[ -n "$COUNT" && "$COUNT" -gt 0 ]]; then
            log_info "Table $TABLE has $COUNT rows"
        else
            log_warn "Table $TABLE is empty or missing"
        fi
    done
    
    # Verify specific data
    TRUST_DOMAIN_COUNT=$(psql "$RESTORE_DB_DSN" -t -c "SELECT count(*) FROM qredin_trust_domains WHERE status='active';" 2>/dev/null | xargs)
    if [[ "$TRUST_DOMAIN_COUNT" -gt 0 ]]; then
        log_info "Active trust domains: $TRUST_DOMAIN_COUNT"
    else
        log_error "No active trust domains found in restored database"
        return 1
    fi
    
    return 0
}

# Test 5: Measure RTO (Recovery Time Objective)
test_measure_rto() {
    log_info "Test 5: Measuring RTO..."
    
    START_TIME=$(date +%s.%N)
    
    LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/backup_*.enc 2>/dev/null | head -1)
    
    if qredin-operator --config /etc/qredin/server.yaml restore-backup \
        --backup-file "$LATEST_BACKUP" \
        --target-dsn "$RESTORE_DB_DSN" \
        --passphrase "$PASSPHRASE" >/dev/null 2>&1; then
        
        END_TIME=$(date +%s.%N)
        RTO=$(echo "$END_TIME - $START_TIME" | bc)
        
        log_info "RTO: ${RTO} seconds"
        
        # Check if RTO meets target (1 hour = 3600 seconds)
        if (( $(echo "$RTO < 3600" | bc -l) )); then
            log_info "RTO meets 1-hour target"
            return 0
        else
            log_warn "RTO exceeds 1-hour target"
            return 1
        fi
    else
        log_error "Restore failed during RTO measurement"
        return 1
    fi
}

# Test 6: Measure RPO (Recovery Point Objective)
test_measure_rpo() {
    log_info "Test 6: Measuring RPO..."
    
    # Get last backup timestamp
    LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/backup_*.enc 2>/dev/null | head -1)
    
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_error "No backup files found"
        return 1
    fi
    
    # Extract timestamp from filename or metadata
    # This would use the backup metadata file
    META_FILE="${LATEST_BACKUP}.meta"
    
    if [[ -f "$META_FILE" ]]; then
        BACKUP_TIME=$(cat "$META_FILE" | jq -r '.timestamp' 2>/dev/null)
        if [[ -n "$BACKUP_TIME" && "$BACKUP_TIME" != "null" ]]; then
            BACKUP_EPOCH=$(date -d "$BACKUP_TIME" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$BACKUP_TIME" +%s 2>/dev/null)
            CURRENT_EPOCH=$(date +%s)
            RPO=$((CURRENT_EPOCH - BACKUP_EPOCH))
            
            log_info "RPO: ${RPO} seconds ($((RPO / 3600)) hours)"
            
            # Check if RPO meets target (24 hours = 86400 seconds)
            if [[ $RPO -lt 86400 ]]; then
                log_info "RPO meets 24-hour target"
                return 0
            else
                log_warn "RPO exceeds 24-hour target"
                return 1
            fi
        fi
    fi
    
    log_warn "Could not determine RPO from metadata"
    return 1
}

# Test 7: Retention policy verification
test_retention_policy() {
    log_info "Test 7: Verifying retention policy..."
    
    # Count backups older than 7 days
    OLD_BACKUPS=$(find "$BACKUP_DIR" -name "backup_*.enc" -mtime +7 2>/dev/null | wc -l)
    
    if [[ $OLD_BACKUPS -eq 0 ]]; then
        log_info "Retention policy: No backups older than 7 days (correct)"
    else
        log_warn "Found $OLD_BACKUPS backups older than 7 days"
    fi
    
    # Count total backups
    TOTAL_BACKUPS=$(find "$BACKUP_DIR" -name "backup_*.enc" 2>/dev/null | wc -l)
    log_info "Total backups: $TOTAL_BACKUPS"
    
    return 0
}

# Main test runner
main() {
    log_info "Starting Qredin Backup Restore Tests"
    log_info "Backup directory: $BACKUP_DIR"
    log_info "Source DB: $DB_DSN"
    log_info "Restore DB: $RESTORE_DB_DSN"
    
    FAILED=0
    
    test_create_backup || ((FAILED++))
    test_verify_backup || ((FAILED++))
    test_restore_backup || ((FAILED++))
    test_verify_restored_data || ((FAILED++))
    test_measure_rto || ((FAILED++))
    test_measure_rpo || ((FAILED++))
    test_retention_policy || ((FAILED++))
    
    echo ""
    if [[ $FAILED -eq 0 ]]; then
        log_info "All tests PASSED"
        exit 0
    else
        log_error "$FAILED test(s) FAILED"
        exit 1
    fi
}

main "$@"