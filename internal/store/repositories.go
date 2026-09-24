package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	ErrNotFound       = errors.New("store: record not found")
	ErrInvalidState   = errors.New("store: invalid state")
	ErrAuditDuplicate = errors.New("store: audit event already recorded")
)

// WithTransaction executes fn in a transaction and rolls back on every error.
// Callers must perform state changes and their audit insert in the same fn.
func WithTransaction(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	if pool == nil || fn == nil {
		return errors.New("store: pool and transaction function are required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: committing transaction: %w", err)
	}
	return nil
}

type TrustDomainRecord struct {
	TrustDomain   spiffeid.TrustDomain
	EnvironmentID string
	Status        string
	Revision      int64
}

type TrustDomainRepository struct{ pool *pgxpool.Pool }

func NewTrustDomainRepository(pool *pgxpool.Pool) (*TrustDomainRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &TrustDomainRepository{pool: pool}, nil
}

func (r *TrustDomainRepository) Put(ctx context.Context, record TrustDomainRecord, expectedRevision *int64) (int64, error) {
	if record.TrustDomain.IsZero() || record.EnvironmentID == "" || !validTrustDomainStatus(record.Status) {
		return 0, ErrInvalidState
	}
	var revision int64
	err := r.pool.QueryRow(ctx, `
		INSERT INTO qredin_trust_domains(trust_domain, environment_id, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (trust_domain) DO UPDATE SET
			environment_id = EXCLUDED.environment_id,
			status = EXCLUDED.status,
			revision = qredin_trust_domains.revision + 1,
			updated_at = now()
		WHERE ($4::BIGINT IS NULL OR qredin_trust_domains.revision = $4)
		RETURNING revision`, record.TrustDomain.String(), record.EnvironmentID, record.Status, expectedRevision).
		Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("store: putting trust domain: %w", err)
	}
	return revision, nil
}

func (r *TrustDomainRepository) Get(ctx context.Context, td spiffeid.TrustDomain) (TrustDomainRecord, error) {
	var record TrustDomainRecord
	var name string
	err := r.pool.QueryRow(ctx, `
		SELECT trust_domain, environment_id, status, revision
		FROM qredin_trust_domains WHERE trust_domain = $1`, td.String()).
		Scan(&name, &record.EnvironmentID, &record.Status, &record.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return TrustDomainRecord{}, ErrNotFound
	}
	if err != nil {
		return TrustDomainRecord{}, fmt.Errorf("store: getting trust domain: %w", err)
	}
	record.TrustDomain, err = spiffeid.TrustDomainFromName(name)
	if err != nil {
		return TrustDomainRecord{}, fmt.Errorf("store: parsing trust domain: %w", err)
	}
	return record, nil
}

type AuthorityRecord struct {
	ID          string
	TrustDomain spiffeid.TrustDomain
	KeyID       string
	Certificate *x509.Certificate
	Lifecycle   string
	NotBefore   time.Time
	NotAfter    time.Time
	Revision    int64
}

type AuthorityRepository struct{ pool *pgxpool.Pool }

func NewAuthorityRepository(pool *pgxpool.Pool) (*AuthorityRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &AuthorityRepository{pool: pool}, nil
}

func (r *AuthorityRepository) Put(ctx context.Context, record AuthorityRecord, expectedRevision *int64) (int64, error) {
	if err := validateAuthority(record); err != nil {
		return 0, err
	}
	var revision int64
	err := r.pool.QueryRow(ctx, `
		INSERT INTO qredin_authorities
			(authority_id, trust_domain, key_id, certificate_der, lifecycle, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (authority_id) DO UPDATE SET
			trust_domain = EXCLUDED.trust_domain,
			key_id = EXCLUDED.key_id,
			certificate_der = EXCLUDED.certificate_der,
			lifecycle = EXCLUDED.lifecycle,
			not_before = EXCLUDED.not_before,
			not_after = EXCLUDED.not_after,
			revision = qredin_authorities.revision + 1,
			updated_at = now()
		WHERE ($8::BIGINT IS NULL OR qredin_authorities.revision = $8)
		RETURNING revision`, record.ID, record.TrustDomain.String(), record.KeyID,
		record.Certificate.Raw, record.Lifecycle, record.NotBefore, record.NotAfter, expectedRevision).
		Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("store: putting authority: %w", err)
	}
	return revision, nil
}

func (r *AuthorityRepository) Transition(ctx context.Context, id, from, to string, expectedRevision int64) (int64, error) {
	if !validAuthorityTransition(from, to) {
		return 0, ErrInvalidState
	}
	var revision int64
	err := r.pool.QueryRow(ctx, `
		UPDATE qredin_authorities
		SET lifecycle = $2, revision = revision + 1, updated_at = now()
		WHERE authority_id = $1 AND lifecycle = $3 AND revision = $4
		RETURNING revision`, id, to, from, expectedRevision).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("store: transitioning authority: %w", err)
	}
	return revision, nil
}

type Queryer interface {
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
}

type AuditEvent struct {
	EventID         string
	EventType       string
	TenantID        string
	EnvironmentID   string
	TrustDomain     string
	SubjectSPIFFEID string
	DecisionID      string
	PolicyRevision  *int64
	Payload         json.RawMessage
	OccurredAt      time.Time
	TraceID         string
	CorrelationID   string
}

type AuditRepository struct{ pool *pgxpool.Pool }

func NewAuditRepository(pool *pgxpool.Pool) (*AuditRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &AuditRepository{pool: pool}, nil
}

func (r *AuditRepository) Append(ctx context.Context, event AuditEvent) error {
	return r.AppendTx(r.pool, ctx, event)
}

// AppendTx appends an audit event inside the transaction owned by q. The
// validation, payload, and idempotency rules are identical to Append.
func (r *AuditRepository) AppendTx(q Queryer, ctx context.Context, event AuditEvent) error {
	if event.EventID == "" || event.EventType == "" || len(event.Payload) == 0 || !json.Valid(event.Payload) || event.OccurredAt.IsZero() {
		return errors.New("store: invalid audit event")
	}
	_, err := q.Exec(ctx, `
		INSERT INTO qredin_audit_events
			(event_id, event_type, tenant_id, environment_id, trust_domain,
			 subject_spiffe_id, decision_id, policy_revision, payload, occurred_at, trace_id, correlation_id)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
			NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10, NULLIF($11, ''), NULLIF($12, ''))
		ON CONFLICT (event_id) DO NOTHING`, event.EventID, event.EventType,
		event.TenantID, event.EnvironmentID, event.TrustDomain, event.SubjectSPIFFEID,
		event.DecisionID, event.PolicyRevision, event.Payload, event.OccurredAt, event.TraceID, event.CorrelationID)
	if err != nil {
		return fmt.Errorf("store: appending audit event: %w", err)
	}
	return nil
}

// NewEventID generates a version-4 UUID suitable as a unique audit event ID.
func NewEventID() (string, error) {
	return uuidv4()
}

func validTrustDomainStatus(status string) bool {
	return status == "prepared" || status == "active" || status == "suspended" || status == "revoked"
}

func validateAuthority(record AuthorityRecord) error {
	if record.ID == "" || record.TrustDomain.IsZero() || record.KeyID == "" || record.Certificate == nil || !validAuthorityState(record.Lifecycle) || !record.NotAfter.After(record.NotBefore) {
		return ErrInvalidState
	}
	return nil
}

func validAuthorityState(state string) bool {
	return state == "prepared" || state == "active" || state == "old" || state == "tainted" || state == "revoked"
}

func validAuthorityTransition(from, to string) bool {
	return from == "prepared" && to == "active" || from == "active" && (to == "old" || to == "tainted") || from == "old" && (to == "tainted" || to == "revoked") || from == "tainted" && to == "revoked"
}
