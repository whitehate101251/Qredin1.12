package policy

import "context"

// PolicyDecisionProvider evaluates an authorization request against a policy
// and returns a decision. The constrained DSL evaluator is the v1 concrete
// implementation; OPA or Cedar providers can be swapped in without touching
// call sites (see ADR 0004).
type PolicyDecisionProvider interface {
	EvaluateDecision(ctx context.Context, request AuthorizationRequest, policy Policy) (AuthorizationDecision, error)
	// HealthCheck reports whether the provider can serve decisions.
	HealthCheck(ctx context.Context) error
}

// NoopRiskProvider is a risk provider that returns no signals and is always
// healthy. It is the default when no external risk provider is configured.
type NoopRiskProvider struct{}

// GetSignals implements RiskProvider.
func (NoopRiskProvider) GetSignals(_ context.Context, _ string) ([]RiskSignal, error) {
	return nil, nil
}

// HealthCheck implements RiskProvider.
func (NoopRiskProvider) HealthCheck(_ context.Context) error {
	return nil
}