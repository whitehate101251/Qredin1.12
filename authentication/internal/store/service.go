package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/authentication/internal/registration"
)

// RegistrationService coordinates durable registration lifecycle operations.
// Every state change and its audit event share one database transaction so a
// caller can never observe an entry without its audit trail, or vice versa.
type RegistrationService struct {
	pool          *pgxpool.Pool
	registrations *RegistrationRepository
	approvals     *RegistrationApprovalRepository
	audit         *AuditRepository
}

func NewRegistrationService(
	pool *pgxpool.Pool,
	registrations *RegistrationRepository,
	approvals *RegistrationApprovalRepository,
	audit *AuditRepository,
) *RegistrationService {
	return &RegistrationService{
		pool:          pool,
		registrations: registrations,
		approvals:     approvals,
		audit:         audit,
	}
}

// Put registers a workload or updates it when expectedRevision is nil. The
// entry is stored as pending; activation requires two distinct approvers.
func (s *RegistrationService) Put(ctx context.Context, entry registration.Entry, expectedRevision *int64) (int64, error) {
	var revision int64
	err := WithTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		revision, err = s.registrations.PutTx(tx, ctx, entry, expectedRevision)
		if err != nil {
			return err
		}
		return s.appendTx(ctx, tx, AuditEvent{
			EventType:       "registration.put",
			TenantID:        entry.TenantID,
			EnvironmentID:   entry.EnvironmentID,
			TrustDomain:     entry.TrustDomain.String(),
			SubjectSPIFFEID: entry.WorkloadID.String(),
			Payload:         json.RawMessage(`{"revision":` + fmt.Sprint(revision) + `}`),
			OccurredAt:      time.Now().UTC(),
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: putting entry: %w", err)
	}
	return revision, nil
}

// Approve records one distinct operator approval for a registration.
func (s *RegistrationService) Approve(ctx context.Context, registrationID, approverID string) error {
	return s.approvals.ApproveTx(s.pool, ctx, registrationID, approverID)
}

// Activate atomically flips a registration to active once two distinct
// approvers have approved it and the expected revision still matches.
func (s *RegistrationService) Activate(ctx context.Context, registrationID string, expectedRevision int64) (int64, error) {
	var revision int64
	err := WithTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		revision, err = s.approvals.ActivateTx(tx, ctx, registrationID, expectedRevision)
		if err != nil {
			return err
		}
		return s.appendTx(ctx, tx, AuditEvent{
			EventType:       "registration.activate",
			EnvironmentID:   "global",
			SubjectSPIFFEID: registrationID,
			Payload:         json.RawMessage(`{"revision":` + fmt.Sprint(revision) + `}`),
			OccurredAt:      time.Now().UTC(),
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: activating %q: %w", registrationID, err)
	}
	return revision, nil
}

// SetStatus transitions a registration between active, suspended, and revoked
// states with optimistic concurrency control. Revoked registrations disappear
// from Get and cannot be reactivated in place.
func (s *RegistrationService) SetStatus(ctx context.Context, id, status string, expectedRevision int64) (int64, error) {
	var revision int64
	err := WithTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		revision, err = s.registrations.SetStatusTx(tx, ctx, id, status, expectedRevision)
		if err != nil {
			return err
		}
		return s.appendTx(ctx, tx, AuditEvent{
			EventType:       "registration.status",
			EnvironmentID:   "global",
			SubjectSPIFFEID: id,
			Payload:         json.RawMessage(`{"revision":` + fmt.Sprint(revision) + `,"status":` + strconv.Quote(status) + `}`),
			OccurredAt:      time.Now().UTC(),
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: setting status of %q: %w", id, err)
	}
	return revision, nil
}

// Get returns an active or suspended registration and its revision. Revoked
// registrations are intentionally not returned to issuance callers.
func (s *RegistrationService) Get(ctx context.Context, id string) (registration.Entry, int64, error) {
	return s.registrations.Get(ctx, id)
}

// Suspend marks a registration as suspended. Suspended registrations
// are not returned by Get and cannot issue credentials until reactivated.
func (s *RegistrationService) Suspend(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, registration.StatusSuspended, expectedRevision)
}

// Revoke marks a registration as revoked. Revoked registrations are
// permanent and cannot be reactivated.
func (s *RegistrationService) Revoke(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, registration.StatusRevoked, expectedRevision)
}

func (s *RegistrationService) appendTx(ctx context.Context, tx pgx.Tx, event AuditEvent) error {
	return s.audit.AppendTx(tx, ctx, event)
}
