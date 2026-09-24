package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/qredin/qredin/internal/policy"
)

// PolicyService coordinates policy lifecycle operations.
type PolicyService struct {
	policyRepo        *PolicyRepository
	auditRepo         *AuditRepository
	approvalRepo      *PolicyApprovalRepository
	healthRepo        interface {
		Check(ctx context.Context) error
	}
	decisionProvider policy.PolicyDecisionProvider
}

// NewPolicyService creates a new policy service.
func NewPolicyService(
	policyRepo *PolicyRepository,
	auditRepo *AuditRepository,
	approvalRepo *PolicyApprovalRepository,
	healthRepo interface {
		Check(ctx context.Context) error
	},
) *PolicyService {
	return &PolicyService{
		policyRepo:        policyRepo,
		auditRepo:         auditRepo,
		approvalRepo:      approvalRepo,
		healthRepo:        healthRepo,
		decisionProvider:  policy.NewDSLProvider(nil),
	}
}

// SetDecisionProvider sets the decision provider for the policy service.
func (s *PolicyService) SetDecisionProvider(provider policy.PolicyDecisionProvider) {
	if provider != nil {
		s.decisionProvider = provider
	}
}

// CreatePolicyVersion creates a new policy version.
func (s *PolicyService) CreatePolicyVersion(ctx context.Context, policy policy.Policy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("policy: invalid policy: %w", err)
	}
	policy.CreatedAt = time.Now().UTC()
	policy.UpdatedAt = policy.CreatedAt

	if err := s.policyRepo.Put(ctx, policy); err != nil {
		return fmt.Errorf("policy: failed to create policy version: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(policy, "created", "system")); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// UpdatePolicyVersion updates a policy version.
func (s *PolicyService) UpdatePolicyVersion(ctx context.Context, policy policy.Policy) error {
	if policy.ID == "" {
		return errors.New("policy: policy id is required")
	}
	if policy.Version <= 0 {
		return errors.New("policy: version must be positive")
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("policy: invalid policy: %w", err)
	}
	policy.UpdatedAt = time.Now().UTC()

	if err := s.policyRepo.Put(ctx, policy); err != nil {
		return fmt.Errorf("policy: failed to update policy version: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(policy, "updated", "system")); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// ActivatePolicyVersion activates a policy version.
func (s *PolicyService) ActivatePolicyVersion(ctx context.Context, id string, version int64, actor string) error {
	pol, err := s.policyRepo.Get(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to get policy for activation: %w", err)
	}

	// Check if policy has at least one approval before activation
	hasApprovals, err := s.approvalRepo.HasApprovals(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to check approvals: %w", err)
	}
	if !hasApprovals {
		return fmt.Errorf("policy: %w", ErrPolicyApprovalRequired)
	}

	pol.Status = policy.PolicyStatusActive
	now := time.Now().UTC()
	pol.ActivatedAt = &now
	pol.UpdatedAt = now

	if err := s.policyRepo.Put(ctx, pol); err != nil {
		return fmt.Errorf("policy: failed to activate policy: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(pol, "activated", actor)); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// RollbackPolicyVersion rolls back a policy version (reactivates suspended).
func (s *PolicyService) RollbackPolicyVersion(ctx context.Context, id string, version int64, actor string) error {
	pol, err := s.policyRepo.Get(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to get policy for rollback: %w", err)
	}

	if pol.Status != policy.PolicyStatusSuspended {
		return errors.New("policy: policy must be suspended to rollback")
	}

	// Check for approvals
	hasApprovals, err := s.approvalRepo.HasApprovals(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to check approvals: %w", err)
	}
	if !hasApprovals {
		return fmt.Errorf("policy: %w", ErrPolicyApprovalRequired)
	}

	pol.Status = policy.PolicyStatusActive
	now := time.Now().UTC()
	pol.ActivatedAt = &now
	pol.UpdatedAt = now
	pol.RevokedAt = nil // Clear revoked timestamp

	if err := s.policyRepo.Put(ctx, pol); err != nil {
		return fmt.Errorf("policy: failed to rollback policy: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(pol, "rollback", actor)); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// SuspendPolicyVersion suspends a policy.
func (s *PolicyService) RolloutPolicyVersion(ctx context.Context, id string, version int64, actor string) error {
	pol, err := s.policyRepo.Get(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to get policy for rollout: %w", err)
	}

	// Only roll out to draft, pending, or suspended
	if pol.Status != policy.PolicyStatusDraft && pol.Status != policy.PolicyStatusPending && pol.Status != policy.PolicyStatusSuspended {
		return errors.New("policy: policy must be draft, pending, or suspended to rollout")
	}

	// Transition to pending for review
	pol.Status = policy.PolicyStatusPending
	now := time.Now().UTC()
	pol.UpdatedAt = now

	if err := s.policyRepo.Put(ctx, pol); err != nil {
		return fmt.Errorf("policy: failed to rollout policy: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(pol, "rollout", actor)); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// RevokePolicyVersion revokes a suspended policy.
func (s *PolicyService) RevokePolicyVersion(ctx context.Context, id string, version int64, actor string) error {
	pol, err := s.policyRepo.Get(ctx, id, version)
	if err != nil {
		return fmt.Errorf("policy: failed to get policy for revocation: %w", err)
	}

	if pol.Status != policy.PolicyStatusSuspended {
		return errors.New("policy: policy must be suspended to revoke")
	}

	pol.Status = policy.PolicyStatusRevoked
	pol.UpdatedAt = time.Now().UTC()

	if err := s.policyRepo.Put(ctx, pol); err != nil {
		return fmt.Errorf("policy: failed to revoke policy: %w", err)
	}

	if err := s.auditRepo.Append(ctx, policyAuditEvent(pol, "revoked", actor)); err != nil {
		return fmt.Errorf("policy: failed to record audit: %w", err)
	}

	return nil
}

// Evaluate evaluates an authorization request against the active policy for a scope.
func (s *PolicyService) Evaluate(
	ctx context.Context,
	request policy.AuthorizationRequest,
	scope policy.PolicyScope,
	riskProviders map[string]policy.RiskProvider,
) (policy.AuthorizationDecision, error) {
	if err := request.Validate(); err != nil {
		return policy.AuthorizationDecision{}, fmt.Errorf("policy: invalid request: %w", err)
	}
	if err := scope.Validate(); err != nil {
		return policy.AuthorizationDecision{}, fmt.Errorf("policy: invalid scope: %w", err)
	}

	if s.healthRepo != nil {
		if err := s.healthRepo.Check(ctx); err != nil {
			return policy.AuthorizationDecision{}, fmt.Errorf("policy: health check failed: %w", err)
		}
	}

	policyObj, err := s.policyRepo.GetActive(ctx, scope)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			return createDenyDecision(request, err, time.Now().UTC(), false), nil
		}
		return policy.AuthorizationDecision{}, fmt.Errorf("policy: failed to get active policy: %w", err)
	}

	decision, err := s.decisionProvider.EvaluateDecision(ctx, request, policyObj)
	if err != nil {
		return policy.AuthorizationDecision{}, fmt.Errorf("policy: failed to evaluate decision: %w", err)
	}

	riskScore := 0.0
	var riskLevel policy.RiskLevel
	for _, provider := range riskProviders {
		signals, err := provider.GetSignals(ctx, request.SubjectSPIFFEID)
		if err != nil {
			continue
		}
		for _, signal := range signals {
			if err := signal.Validate(); err != nil {
				continue
			}
			if signal.Score > riskScore {
				riskScore = signal.Score
				riskLevel = signal.Level
			}
		}
	}

	if decision.Decision == policy.DecisionAllow && riskScore >= 0.8 {
		decision.Decision = policy.DecisionDeny
		decision.Reason = fmt.Sprintf("risk-based override: high risk score %.2f", riskScore)
	} else if decision.Decision == policy.DecisionAllow && riskScore >= 0.95 {
		decision.Decision = policy.DecisionDeny
		decision.Reason = fmt.Sprintf("risk-based override: critical risk score %.2f", riskScore)
	}

	auditEvent := policyAuthorizationDecision(request, decision.Decision, policyObj.ID, policyObj.Version, decision.MatchedRule, riskScore, string(riskLevel))
	if err := s.auditRepo.Append(ctx, auditEvent); err != nil {
		return policy.AuthorizationDecision{}, fmt.Errorf("policy: failed to record audit: %w", err)
	}

	decision.CacheHit = false
	decision.EvaluatedAt = time.Now().UTC()
	decision.TraceID = request.TraceID
	decision.CorrelationID = request.CorrelationID
	return decision, nil
}

// createAllowDecision creates an authorization decision for allow.
func createAllowDecision(
	request policy.AuthorizationRequest,
	decision policy.Decision,
	policyID string,
	policyVersion int64,
	matchedRule *policy.Rule,
	reason string,
	evaluatedAt time.Time,
	cacheHit bool,
) policy.AuthorizationDecision {
	explanation := json.RawMessage("")
	if matchedRule != nil {
		explanation = json.RawMessage(matchedRule.Explanation)
	}

	return policy.AuthorizationDecision{
		RequestID:      request.RequestID,
		Decision:       decision,
		PolicyID:       policyID,
		PolicyVersion:  policyVersion,
		MatchedRule:    matchedRule,
		Reason:         reason,
		EvaluatedAt:    evaluatedAt,
		CacheHit:       cacheHit,
		Explanation:    explanation,
		TraceID:        request.TraceID,
		CorrelationID: request.CorrelationID,
	}
}

// createDenyDecision creates an authorization decision for deny.
func createDenyDecision(
	request policy.AuthorizationRequest,
	error error,
	evaluatedAt time.Time,
	cacheHit bool,
) policy.AuthorizationDecision {
	return policy.AuthorizationDecision{
		RequestID:   request.RequestID,
		Decision:    policy.DecisionDeny,
		Reason:      error.Error(),
		EvaluatedAt: evaluatedAt,
		CacheHit:    cacheHit,
	}
}

// policyAuditEvent creates an audit event for a policy change.
func policyAuditEvent(policy policy.Policy, action, actor string) AuditEvent {
	payload, _ := json.Marshal(map[string]interface{}{
		"policy_id": policy.ID,
		"version":   policy.Version,
		"status":    policy.Status,
		"action":    action,
		"actor":     actor,
		"previous":  nil,
		"new":       policy,
	})

	return AuditEvent{
		EventID:         "", // Will be generated by audit repo
		EventType:       "policy." + action,
		TenantID:        policy.Scope.TenantID,
		EnvironmentID:   policy.Scope.EnvironmentID,
		TrustDomain:     policy.Scope.TrustDomain.String(),
		SubjectSPIFFEID: policy.ID,
		DecisionID:      policy.ID,
		PolicyRevision:  &policy.Version,
		Payload:         json.RawMessage(payload),
		OccurredAt:      time.Now().UTC(),
	}
}

// policyAuthorizationDecision creates an audit event for an authorization decision.
func policyAuthorizationDecision(
	request policy.AuthorizationRequest,
	decision policy.Decision,
	policyID string,
	policyVersion int64,
	matchedRule *policy.Rule,
	riskScore float64,
	riskLevel string,
) AuditEvent {
	payload, _ := json.Marshal(map[string]interface{}{
		"request_id":     request.RequestID,
		"subject":        request.SubjectSPIFFEID,
		"action":         request.Action,
		"resource":       request.Resource,
		"decision":       decision,
		"policy_id":      policyID,
		"policy_version": policyVersion,
		"matched_rule":   matchedRule,
		"risk_score":     riskScore,
		"risk_level":     riskLevel,
		"timestamp":      request.Timestamp,
		"context":        request.Context,
	})

	return AuditEvent{
		EventID:         "", // Will be generated by audit repo
		EventType:       "authorization.decision",
		TenantID:        "",
		EnvironmentID:   "",
		TrustDomain:     "",
		SubjectSPIFFEID: request.SubjectSPIFFEID,
		DecisionID:      request.RequestID,
		PolicyRevision:  &policyVersion,
		Payload:         json.RawMessage(payload),
		OccurredAt:      time.Now().UTC(),
	}
}
