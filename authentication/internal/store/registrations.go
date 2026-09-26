package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/authentication/internal/registration"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var ErrRevisionConflict = errors.New("store: revision conflict")

// RegistrationRepository persists approved workload bindings. The database is
// the source of truth; callers must not fall back to an in-memory registry when
// a write or read fails.
type RegistrationRepository struct {
	pool *pgxpool.Pool
}

func NewRegistrationRepository(pool *pgxpool.Pool) (*RegistrationRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &RegistrationRepository{pool: pool}, nil
}

// Put inserts an entry or updates it when expectedRevision is nil. When a
// revision is supplied, the update succeeds only if the stored revision still
// matches, preventing lost administrative updates.
func (r *RegistrationRepository) Put(ctx context.Context, entry registration.Entry, expectedRevision *int64) (int64, error) {
	revision, err := r.PutTx(r.pool, ctx, entry, expectedRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	return revision, err
}

// Get returns an active or suspended registration and its revision. Revoked
// registrations are intentionally not returned to issuance callers.
func (r *RegistrationRepository) Get(ctx context.Context, id string) (registration.Entry, int64, error) {
	var (
		entry                             registration.Entry
		trustDomain, workloadID, parentID string
		selectorsJSON                     []byte
		revision                          int64
		status                            string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT tenant_id, environment_id, trust_domain, workload_spiffe_id,
		       parent_agent_spiffe_id, selectors, revision, status
		FROM qredin_registrations
		WHERE registration_id = $1`, id).
		Scan(&entry.TenantID, &entry.EnvironmentID, &trustDomain, &workloadID,
			&parentID, &selectorsJSON, &revision, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration.Entry{}, 0, registration.ErrNoMatch
	}
	if err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: getting registration %q: %w", id, err)
	}
	if status == "revoked" {
		return registration.Entry{}, 0, registration.ErrNoMatch
	}
	entry.Status = status
	entry.ID = id
	entry.TrustDomain, err = spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: parsing registration trust domain: %w", err)
	}
	entry.WorkloadID, err = spiffeid.FromString(workloadID)
	if err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: parsing registration workload ID: %w", err)
	}
	entry.ParentAgentID, err = spiffeid.FromString(parentID)
	if err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: parsing registration parent ID: %w", err)
	}
	var rawSelectors []attestation.Selector
	if err := json.Unmarshal(selectorsJSON, &rawSelectors); err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: parsing registration selectors: %w", err)
	}
	entry.Selectors, err = attestation.NewSelectors(rawSelectors...)
	if err != nil {
		return registration.Entry{}, 0, fmt.Errorf("store: validating registration selectors: %w", err)
	}
	return entry, revision, nil
}

// PutTx is the transactional variant of Put. Callers must pass the same
// queryer that owns the surrounding transaction so the state change and its
// audit insert share one atomic boundary.
func (r *RegistrationRepository) PutTx(q Queryer, ctx context.Context, entry registration.Entry, expectedRevision *int64) (int64, error) {
	if err := validateEntryForStore(entry); err != nil {
		return 0, err
	}
	if entry.Status == "" {
		entry.Status = registration.StatusActive
	}
	selectors, err := json.Marshal(entry.Selectors)
	if err != nil {
		return 0, fmt.Errorf("store: encoding registration selectors: %w", err)
	}
	const query = `
		INSERT INTO qredin_registrations
			(registration_id, tenant_id, environment_id, trust_domain,
			 workload_spiffe_id, parent_agent_spiffe_id, selectors, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (registration_id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			environment_id = EXCLUDED.environment_id,
			trust_domain = EXCLUDED.trust_domain,
			workload_spiffe_id = EXCLUDED.workload_spiffe_id,
			parent_agent_spiffe_id = EXCLUDED.parent_agent_spiffe_id,
			selectors = EXCLUDED.selectors,
			status = EXCLUDED.status,
			revision = qredin_registrations.revision + 1,
			updated_at = now()
		WHERE ($9::BIGINT IS NULL OR qredin_registrations.revision = $9)
		RETURNING revision`
	var revision int64
	err = q.QueryRow(ctx, query,
		entry.ID, entry.TenantID, entry.EnvironmentID, entry.TrustDomain.String(),
		entry.WorkloadID.String(), entry.ParentAgentID.String(), selectors, entry.Status, expectedRevision).
		Scan(&revision)
	if err != nil {
		return 0, fmt.Errorf("store: putting registration %q: %w", entry.ID, err)
	}
	return revision, nil
}

// SetStatusTx atomically transitions a registration's lifecycle state inside
// a transaction. Revoked registrations are never returned by Get, so a
// caller that issues credentials must re-read the entry after the transition.
func (r *RegistrationRepository) SetStatusTx(q Queryer, ctx context.Context, id, status string, expectedRevision int64) (int64, error) {
	if status != registration.StatusActive && status != registration.StatusSuspended && status != registration.StatusRevoked {
		return 0, registration.ErrInvalidRegistration
	}
	var revision int64
	err := q.QueryRow(ctx, `
		UPDATE qredin_registrations
		SET status = $2, revision = revision + 1, updated_at = now()
		WHERE registration_id = $1 AND revision = $3
		RETURNING revision`, id, status, expectedRevision).Scan(&revision)
	if err != nil {
		return 0, fmt.Errorf("store: setting registration %q status: %w", id, err)
	}
	return revision, nil
}

// SetStatus is the pool-backed convenience for SetStatusTx.
func (r *RegistrationRepository) SetStatus(ctx context.Context, id, status string, expectedRevision int64) (int64, error) {
	return r.SetStatusTx(r.pool, ctx, id, status, expectedRevision)
}

func validateEntryForStore(entry registration.Entry) error {
	if entry.ID == "" || entry.TenantID == "" || entry.EnvironmentID == "" {
		return errors.New("store: registration identity fields are required")
	}
	if entry.TrustDomain.IsZero() || !entry.WorkloadID.IsWorkload() || !entry.WorkloadID.MemberOf(entry.TrustDomain) {
		return errors.New("store: registration workload is outside its trust domain")
	}
	if !entry.ParentAgentID.IsWorkload() || len(entry.Selectors) == 0 {
		return errors.New("store: registration parent and selectors are required")
	}
	if entry.Status != "" && entry.Status != registration.StatusActive && entry.Status != registration.StatusSuspended && entry.Status != registration.StatusRevoked {
		return registration.ErrInvalidRegistration
	}
	for _, selector := range entry.Selectors {
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("store: invalid registration selector: %w", err)
		}
	}
	return nil
}

// RequiresApproval checks whether a registration entry requires additional
// operator approval before it can be activated. Returns true if the entry
// status is pending or if fewer than 2 approvals exist.
func (r *RegistrationRepository) RequiresApproval(ctx context.Context, id string) (bool, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT approver_id) FROM qredin_registration_approvals WHERE registration_id = $1`,
		id,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store: checking approval requirement: %w", err)
	}
	return count < 2, nil
}
