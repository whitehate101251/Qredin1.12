package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/internal/policy"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	ErrPolicyNotFound      = errors.New("store: policy not found")
	ErrPolicyAlreadyExists = errors.New("store: policy already exists")
	ErrInvalidPolicyData   = errors.New("store: invalid policy data")
	ErrPolicyApprovalRequired = errors.New("store: policy approval required for activation")
)

// PolicyRecord represents a policy record for storage.
type PolicyRecord struct {
	ID              string
	Version         int64
	TenantID        string
	EnvironmentID   string
	TrustDomain     string
	SubjectSPIFFEID sql.NullString
	Rules           []byte // JSON encoded
	Status          string
	Approvers       []byte // JSON encoded
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ActivatedAt     sql.NullTime
	RevokedAt       sql.NullTime
	Description     sql.NullString
}

// PolicyRepository persists policy data.
type PolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyRepository creates a new policy repository.
func NewPolicyRepository(pool *pgxpool.Pool) (*PolicyRepository, error) {
	if pool == nil {
		return nil, errors.New("store: postgres pool is required")
	}
	return &PolicyRepository{pool: pool}, nil
}

// Put stores a policy version.
func (r *PolicyRepository) Put(ctx context.Context, policy policy.Policy) error {
	if policy.Version <= 0 {
		return fmt.Errorf("%w: version must be positive", ErrInvalidPolicyData)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("%w: invalid policy: %v", ErrInvalidPolicyData, err)
	}

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal rules: %v", ErrInvalidPolicyData, err)
	}
	approversJSON, err := json.Marshal(policy.Approvers)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal approvers: %v", ErrInvalidPolicyData, err)
	}

	var description sql.NullString
	if policy.Description != "" {
		description.String = policy.Description
		description.Valid = true
	}

	var activatedAt sql.NullTime
	if policy.ActivatedAt != nil && !policy.ActivatedAt.IsZero() {
		activatedAt.Time = *policy.ActivatedAt
		activatedAt.Valid = true
	}

	var revokedAt sql.NullTime
	if policy.RevokedAt != nil && !policy.RevokedAt.IsZero() {
		revokedAt.Time = *policy.RevokedAt
		revokedAt.Valid = true
	}

	var subjectSPIFFEID sql.NullString
	if policy.Scope.SubjectSPIFFEID != "" {
		subjectSPIFFEID.String = policy.Scope.SubjectSPIFFEID
		subjectSPIFFEID.Valid = true
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO qredin_policies
			(id, version, tenant_id, environment_id, trust_domain, subject_spiffe_id, rules, status, approvers, created_at, updated_at, activated_at, revoked_at, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id, version) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			environment_id = EXCLUDED.environment_id,
			trust_domain = EXCLUDED.trust_domain,
			subject_spiffe_id = EXCLUDED.subject_spiffe_id,
			rules = EXCLUDED.rules,
			status = EXCLUDED.status,
			approvers = EXCLUDED.approvers,
			updated_at = EXCLUDED.updated_at,
			activated_at = EXCLUDED.activated_at,
			revoked_at = EXCLUDED.revoked_at,
			description = EXCLUDED.description`,
		policy.ID, policy.Version,
		policy.Scope.TenantID, policy.Scope.EnvironmentID, policy.Scope.TrustDomain.String(),
		subjectSPIFFEID, rulesJSON, string(policy.Status), approversJSON,
		policy.CreatedAt, policy.UpdatedAt, activatedAt, revokedAt, description)

	if err != nil {
		return fmt.Errorf("%w: failed to store policy: %v", ErrInvalidPolicyData, err)
	}
	return nil
}

// Get retrieves a specific policy version.
func (r *PolicyRepository) Get(ctx context.Context, id string, version int64) (policy.Policy, error) {
	var record PolicyRecord
	err := r.pool.QueryRow(ctx, `
		SELECT id, version, tenant_id, environment_id, trust_domain, subject_spiffe_id, rules, status, approvers, created_at, updated_at, activated_at, revoked_at, description
		FROM qredin_policies WHERE id = $1 AND version = $2`, id, version).
		Scan(&record.ID, &record.Version, &record.TenantID, &record.EnvironmentID, &record.TrustDomain,
			&record.SubjectSPIFFEID, &record.Rules, &record.Status, &record.Approvers,
			&record.CreatedAt, &record.UpdatedAt, &record.ActivatedAt, &record.RevokedAt, &record.Description)

	if errors.Is(err, pgx.ErrNoRows) {
		return policy.Policy{}, fmt.Errorf("%w: policy %s version %d not found: %w", ErrPolicyNotFound, id, version, err)
	}
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to get policy: %v", ErrInvalidPolicyData, err)
	}

	policyObj, err := record.toPolicy()
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to convert record to policy: %v", ErrInvalidPolicyData, err)
	}
	return policyObj, nil
}

// GetLatest retrieves the latest version of a policy.
func (r *PolicyRepository) GetLatest(ctx context.Context, id string) (policy.Policy, error) {
	var record PolicyRecord
	err := r.pool.QueryRow(ctx, `
		SELECT id, version, tenant_id, environment_id, trust_domain, subject_spiffe_id, rules, status, approvers, created_at, updated_at, activated_at, revoked_at, description
		FROM qredin_policies WHERE id = $1 ORDER BY version DESC LIMIT 1`, id).
		Scan(&record.ID, &record.Version, &record.TenantID, &record.EnvironmentID, &record.TrustDomain,
			&record.SubjectSPIFFEID, &record.Rules, &record.Status, &record.Approvers,
			&record.CreatedAt, &record.UpdatedAt, &record.ActivatedAt, &record.RevokedAt, &record.Description)

	if errors.Is(err, pgx.ErrNoRows) {
		return policy.Policy{}, fmt.Errorf("%w: policy %s not found: %w", ErrPolicyNotFound, id, err)
	}
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to get latest policy: %v", ErrInvalidPolicyData, err)
	}

	policyObj, err := record.toPolicy()
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to convert record to policy: %v", ErrInvalidPolicyData, err)
	}
	return policyObj, nil
}

// GetActive retrieves the latest active policy for a scope.
func (r *PolicyRepository) GetActive(ctx context.Context, scope policy.PolicyScope) (policy.Policy, error) {
	var record PolicyRecord
	err := r.pool.QueryRow(ctx, `
		SELECT id, version, tenant_id, environment_id, trust_domain, subject_spiffe_id, rules, status, approvers, created_at, updated_at, activated_at, revoked_at, description
		FROM qredin_policies 
		WHERE tenant_id = $1 AND environment_id = $2 AND trust_domain = $3 AND status = $4
		ORDER BY version DESC LIMIT 1`, scope.TenantID, scope.EnvironmentID, scope.TrustDomain.String(), policy.PolicyStatusActive).
		Scan(&record.ID, &record.Version, &record.TenantID, &record.EnvironmentID, &record.TrustDomain,
			&record.SubjectSPIFFEID, &record.Rules, &record.Status, &record.Approvers,
			&record.CreatedAt, &record.UpdatedAt, &record.ActivatedAt, &record.RevokedAt, &record.Description)

	if errors.Is(err, pgx.ErrNoRows) {
		return policy.Policy{}, fmt.Errorf("%w: no active policy found for scope: %w", ErrPolicyNotFound, err)
	}
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to get active policy: %v", ErrInvalidPolicyData, err)
	}

	policyObj, err := record.toPolicy()
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%w: failed to convert record to policy: %v", ErrInvalidPolicyData, err)
	}
	return policyObj, nil
}

// ListByScope lists all policies for a scope.
func (r *PolicyRepository) ListByScope(ctx context.Context, scope policy.PolicyScope) ([]policy.Policy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, version, tenant_id, environment_id, trust_domain, subject_spiffe_id, rules, status, approvers, created_at, updated_at, activated_at, revoked_at, description
		FROM qredin_policies 
		WHERE tenant_id = $1 AND environment_id = $2 AND trust_domain = $3
		ORDER BY version DESC`, scope.TenantID, scope.EnvironmentID, scope.TrustDomain.String())
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list policies: %v", ErrInvalidPolicyData, err)
	}
	defer rows.Close()

	var policies []policy.Policy
	for rows.Next() {
		var record PolicyRecord
		err := rows.Scan(&record.ID, &record.Version, &record.TenantID, &record.EnvironmentID, &record.TrustDomain,
			&record.SubjectSPIFFEID, &record.Rules, &record.Status, &record.Approvers,
			&record.CreatedAt, &record.UpdatedAt, &record.ActivatedAt, &record.RevokedAt, &record.Description)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to scan policy row: %v", ErrInvalidPolicyData, err)
		}

		policyObj, err := record.toPolicy()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to convert record to policy: %v", ErrInvalidPolicyData, err)
		}
		policies = append(policies, policyObj)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: error iterating policy rows: %v", ErrInvalidPolicyData, err)
	}
	return policies, nil
}

// toPolicy converts a PolicyRecord to a policy.Policy.
func (r *PolicyRecord) toPolicy() (policy.Policy, error) {
	var rules []policy.Rule
	if len(r.Rules) > 0 {
		if err := json.Unmarshal(r.Rules, &rules); err != nil {
			return policy.Policy{}, fmt.Errorf("failed to unmarshal rules: %w", err)
		}
	}

	var approvers []string
	if len(r.Approvers) > 0 {
		if err := json.Unmarshal(r.Approvers, &approvers); err != nil {
			return policy.Policy{}, fmt.Errorf("failed to unmarshal approvers: %w", err)
		}
	}

	var activatedAt *time.Time
	if r.ActivatedAt.Valid {
		t := r.ActivatedAt.Time
		activatedAt = &t
	}

	var revokedAt *time.Time
	if r.RevokedAt.Valid {
		t := r.RevokedAt.Time
		revokedAt = &t
	}

	var description string
	if r.Description.Valid {
		description = r.Description.String
	}

	td, err := spiffeid.TrustDomainFromName(r.TrustDomain)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("failed to parse trust domain: %w", err)
	}

	return policy.Policy{
		ID:      r.ID,
		Version: r.Version,
		Scope: policy.PolicyScope{
			TenantID:        r.TenantID,
			EnvironmentID:   r.EnvironmentID,
			TrustDomain:     td,
			SubjectSPIFFEID: r.SubjectSPIFFEID.String,
		},
		Rules:       rules,
		Status:      policy.PolicyStatus(r.Status),
		Approvers:   approvers,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		ActivatedAt: activatedAt,
		RevokedAt:   revokedAt,
		Description: description,
	}, nil
}

// Delete removes a policy version.
func (r *PolicyRepository) Delete(ctx context.Context, id string, version int64) error {
	result, err := r.pool.Exec(ctx, `
		DELETE FROM qredin_policies WHERE id = $1 AND version = $2`, id, version)
	if err != nil {
		return fmt.Errorf("%w: failed to delete policy: %v", ErrInvalidPolicyData, err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: policy %s version %d not found", ErrPolicyNotFound, id, version)
	}
	return nil
}

// CreatePolicyTable creates the policies table if it doesn't exist.
func CreatePolicyTable(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("store: postgres pool is required")
	}
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS qredin_policies (
			id TEXT NOT NULL,
			version BIGINT NOT NULL,
			tenant_id TEXT NOT NULL,
			environment_id TEXT NOT NULL,
			trust_domain TEXT NOT NULL,
			subject_spiffe_id TEXT,
			rules JSONB NOT NULL,
			status TEXT NOT NULL,
			approvers JSONB,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			activated_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			description TEXT,
			PRIMARY KEY (id, version)
		)`)
	if err != nil {
		return fmt.Errorf("store: failed to create policy table: %w", err)
	}
	return nil
}
