// Package registration provides the registration lifecycle service.
package registration

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// TxManager handles transaction boundaries for operations that must
// atomically combine state changes with audit events.
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(pgx.Tx) error) error
}

// RegistrationStore handles registration persistence operations.
type RegistrationStore interface {
	Put(ctx context.Context, entry Entry, expectedRevision *int64) (int64, error)
	Get(ctx context.Context, id string) (Entry, int64, error)
	SetStatus(ctx context.Context, id, status string, expectedRevision int64) (int64, error)
	Suspend(ctx context.Context, id string, expectedRevision int64) (int64, error)
	Revoke(ctx context.Context, id string, expectedRevision int64) (int64, error)
}

// ApprovalStore handles approval operations.
type ApprovalStore interface {
	Approve(ctx context.Context, registrationID, approverID string) error
	Activate(ctx context.Context, registrationID string, expectedRevision int64) (int64, error)
}

// AuditStore handles audit event recording.
type AuditStore interface {
	RecordRegistrationChange(event ChangeEvent) error
}

// Service coordinates durable registration lifecycle operations with
// transactional consistency and audit trail. Every state change and its
// audit event share one transaction so a caller can never observe an
// entry without its audit trail, or vice versa.
type Service struct {
	txManager     TxManager
	registrations RegistrationStore
	approvals     ApprovalStore
	audit         AuditStore
}

// NewService creates a RegistrationService with the given executors.
func NewService(
	txManager TxManager,
	registrations RegistrationStore,
	approvals ApprovalStore,
	audit AuditStore,
) *Service {
	return &Service{
		txManager:     txManager,
		registrations: registrations,
		approvals:     approvals,
		audit:         audit,
	}
}

// Put registers a workload or updates it when expectedRevision is nil.
func (s *Service) Put(ctx context.Context, entry Entry, expectedRevision *int64) (int64, error) {
	var revision int64
	err := s.txManager.WithTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		revision, err = s.registrations.Put(ctx, entry, expectedRevision)
		if err != nil {
			return err
		}
		return s.audit.RecordRegistrationChange(ChangeEvent{
			Action:         "put",
			RegistrationID: entry.ID,
			Status:         entry.Status,
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: putting entry: %w", err)
	}
	return revision, nil
}

// Suspend marks a registration as suspended. Suspended registrations
// are not returned by Get and cannot issue credentials until reactivated.
func (s *Service) Suspend(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, StatusSuspended, expectedRevision)
}

// Revoke marks a registration as revoked. Revoked registrations are
// permanent and cannot be reactivated.
func (s *Service) Revoke(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, StatusRevoked, expectedRevision)
}

// SetStatus transitions a registration between active, suspended, and
// revoked states with optimistic concurrency control.
func (s *Service) SetStatus(ctx context.Context, id, status string, expectedRevision int64) (int64, error) {
	if status != StatusActive && status != StatusSuspended && status != StatusRevoked {
		return 0, ErrInvalidRegistration
	}
	var revision int64
	err := s.txManager.WithTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		revision, err = s.registrations.SetStatus(ctx, id, status, expectedRevision)
		if err != nil {
			return err
		}
		return s.audit.RecordRegistrationChange(ChangeEvent{
			Action:         "status_change",
			RegistrationID: id,
			Status:         status,
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: setting status of %q: %w", id, err)
	}
	return revision, nil
}

// Activate atomically flips a registration to active once two distinct
// approvers have approved it and the expected revision still matches.
func (s *Service) Activate(ctx context.Context, registrationID string, expectedRevision int64) (int64, error) {
	var revision int64
	err := s.txManager.WithTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		revision, err = s.approvals.Activate(ctx, registrationID, expectedRevision)
		if err != nil {
			return err
		}
		return s.audit.RecordRegistrationChange(ChangeEvent{
			Action:         "activate",
			RegistrationID: registrationID,
			Status:         StatusActive,
		})
	})
	if err != nil {
		return 0, fmt.Errorf("registration: activating %q: %w", registrationID, err)
	}
	return revision, nil
}

// Approve records one distinct operator approval for a registration.
// Activation requires two distinct approvals.
func (s *Service) Approve(ctx context.Context, registrationID, approverID string) error {
	if registrationID == "" || approverID == "" {
		return ErrInvalidRegistration
	}
	return s.approvals.Approve(ctx, registrationID, approverID)
}

// Get returns an active or suspended registration and its revision.
// Revoked registrations are intentionally not returned to issuance callers.
func (s *Service) Get(ctx context.Context, registrationID string) (Entry, int64, error) {
	return s.registrations.Get(ctx, registrationID)
}
