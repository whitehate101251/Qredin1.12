package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RegistrationApprovalRepository implements two-person registration
// activation. The caller must already be authenticated and authorized as an
// operator; this repository records distinct approval identities durably.
type RegistrationApprovalRepository struct{ pool *pgxpool.Pool }

func NewRegistrationApprovalRepository(pool *pgxpool.Pool) (*RegistrationApprovalRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &RegistrationApprovalRepository{pool: pool}, nil
}

func (r *RegistrationApprovalRepository) Approve(ctx context.Context, registrationID, approverID string) error {
	return r.ApproveTx(r.pool, ctx, registrationID, approverID)
}

func (r *RegistrationApprovalRepository) ApproveTx(q Queryer, ctx context.Context, registrationID, approverID string) error {
	if registrationID == "" || approverID == "" {
		return errors.New("store: registration and approver IDs are required")
	}
	_, err := q.Exec(ctx, `
		INSERT INTO qredin_registration_approvals(registration_id, approver_id)
		VALUES ($1, $2) ON CONFLICT (registration_id, approver_id) DO NOTHING`, registrationID, approverID)
	if err != nil {
		return fmt.Errorf("store: recording registration approval: %w", err)
	}
	return nil
}

func (r *RegistrationApprovalRepository) Activate(ctx context.Context, registrationID string, expectedRevision int64) (int64, error) {
	return r.ActivateTx(r.pool, ctx, registrationID, expectedRevision)
}

func (r *RegistrationApprovalRepository) ActivateTx(q Queryer, ctx context.Context, registrationID string, expectedRevision int64) (int64, error) {
	var revision int64
	err := q.QueryRow(ctx, `
		UPDATE qredin_registrations
		SET status = 'active', revision = revision + 1, updated_at = now()
		WHERE registration_id = $1 AND revision = $2
		  AND (SELECT count(DISTINCT approver_id) FROM qredin_registration_approvals
		       WHERE registration_id = $1) >= 2
		RETURNING revision`, registrationID, expectedRevision).Scan(&revision)
	if err != nil {
		return 0, fmt.Errorf("store: activating registration: %w", err)
	}
	return revision, nil
}
