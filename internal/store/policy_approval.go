package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrApprovalNotFound = errors.New("store: approval not found")
)

// PolicyApprovalRecord represents a single approval entry.
type PolicyApprovalRecord struct {
	PolicyID       string
	Version        int64
	ApproverSPID   string
	ApprovedAt     time.Time
}

// PolicyApprovalRepository persists policy approval records.
type PolicyApprovalRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyApprovalRepository creates a new policy approval repository.
func NewPolicyApprovalRepository(pool *pgxpool.Pool) (*PolicyApprovalRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &PolicyApprovalRepository{pool: pool}, nil
}

// Add records an approval for a policy version.
func (r *PolicyApprovalRepository) Add(ctx context.Context, policyID string, version int64, approverSPID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO qredin_policy_approvals (policy_id, version, approver_spiffe_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (policy_id, version, approver_spiffe_id) DO NOTHING`,
		policyID, version, approverSPID)
	if err != nil {
		return fmt.Errorf("store: failed to record approval: %w", err)
	}
	return nil
}

// HasApprovals reports whether the policy version has at least one approval.
func (r *PolicyApprovalRepository) HasApprovals(ctx context.Context, policyID string, version int64) (bool, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM qredin_policy_approvals
		WHERE policy_id = $1 AND version = $2`, policyID, version).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store: failed to check approvals: %w", err)
	}
	return count > 0, nil
}

// CountApprovals returns the number of approvals for a policy version.
func (r *PolicyApprovalRepository) CountApprovals(ctx context.Context, policyID string, version int64) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM qredin_policy_approvals
		WHERE policy_id = $1 AND version = $2`, policyID, version).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: failed to count approvals: %w", err)
	}
	return count, nil
}

// ListApprovals returns all approval records for a policy version.
func (r *PolicyApprovalRepository) ListApprovals(ctx context.Context, policyID string, version int64) ([]PolicyApprovalRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT approver_spiffe_id, approved_at
		FROM qredin_policy_approvals
		WHERE policy_id = $1 AND version = $2
		ORDER BY approved_at ASC`, policyID, version)
	if err != nil {
		return nil, fmt.Errorf("store: failed to list approvals: %w", err)
	}
	defer rows.Close()

	var records []PolicyApprovalRecord
	for rows.Next() {
		var rec PolicyApprovalRecord
		if err := rows.Scan(&rec.ApproverSPID, &rec.ApprovedAt); err != nil {
			return nil, fmt.Errorf("store: failed to scan approval row: %w", err)
		}
		rec.PolicyID = policyID
		rec.Version = version
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: error iterating approval rows: %w", err)
	}
	return records, nil
}
