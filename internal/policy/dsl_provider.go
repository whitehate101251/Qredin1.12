package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// DSLProvider is a PolicyDecisionProvider that evaluates requests
// using the constrained Qredin DSL (v1 per ADR 0004).
type DSLProvider struct {
	cache *PolicyDecisionCache
}

// NewDSLProvider creates a DSL decision provider with an optional cache.
func NewDSLProvider(cache *PolicyDecisionCache) *DSLProvider {
	return &DSLProvider{cache: cache}
}

// EvaluateDecision evaluates a request against a policy using the DSL engine.
func (p *DSLProvider) EvaluateDecision(ctx context.Context, request AuthorizationRequest, pol Policy) (AuthorizationDecision, error) {
	if pol.Rules == nil || len(pol.Rules) == 0 {
		return AuthorizationDecision{}, fmt.Errorf("policy has no rules")
	}

	// Check cache
	if p.cache != nil {
		if entry, ok := p.cache.Get(request.RequestID); ok {
			return AuthorizationDecision{
				RequestID:     request.RequestID,
				Decision:      entry.Decision,
				PolicyID:      entry.PolicyID,
				PolicyVersion: entry.PolicyVersion,
				EvaluatedAt:   entry.EvaluatedAt,
				CacheHit:      true,
			}, nil
		}
	}

	// Evaluate policy
	decision, matchedRule := pol.Evaluate(request)
	now := time.Now().UTC()

	reason := "default deny"
	if matchedRule != nil {
		reason = matchedRule.Explanation
	}

	// Check fail-closed policies
	isFailClosed := false
	if p.cache != nil {
		isFailClosed = p.cache.IsFailClosed(pol.ID)
	}

	if decision == DecisionAllow && isFailClosed {
		decision = DecisionDeny
		reason = "fail-closed policy override"
	}

	// Build explainability trace
	explanation := make(json.RawMessage, 0)
	if matchedRule != nil {
		trace := matchedRule.Condition().Trace(request, request.Context, nil)
		if trace != nil {
			if data, err := json.Marshal(trace); err == nil {
				explanation = data
			}
		}
	}

	result := AuthorizationDecision{
		RequestID:     request.RequestID,
		Decision:      decision,
		PolicyID:      pol.ID,
		PolicyVersion: pol.Version,
		MatchedRule:   matchedRule,
		Reason:        reason,
		EvaluatedAt:   now,
		CacheHit:      false,
		Explanation:   explanation,
	}

	// Cache the result
	if p.cache != nil {
		p.cache.Set(PolicyDecisionCacheEntry{
			RequestID:     request.RequestID,
			PolicyID:      pol.ID,
			PolicyVersion: pol.Version,
			Decision:      decision,
			EvaluatedAt:   now,
			ExpiresAt:     now.Add(5 * time.Minute),
			MatchedRule:   matchedRule.ID,
		})
	}

	return result, nil
}

// HealthCheck reports whether the provider is healthy.
func (p *DSLProvider) HealthCheck(ctx context.Context) error {
	return nil
}