package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	ErrInvalidPolicy       = errors.New("policy: invalid policy")
	ErrInvalidDecision     = errors.New("policy: invalid decision")
	ErrRevisionConflict    = errors.New("policy: revision conflict")
	ErrPolicyNotFound      = errors.New("policy: not found")
	ErrInvalidScope        = errors.New("policy: invalid scope")
	ErrInvalidRule         = errors.New("policy: invalid rule")
	ErrDefaultDenyViolated = errors.New("policy: default deny violated")
)

// Effect represents the outcome of a policy rule.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Decision represents the final authorization decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// PolicyScope defines the scope of a policy (tenant, environment, trust domain).
type PolicyScope struct {
	TenantID        string
	EnvironmentID   string
	TrustDomain     spiffeid.TrustDomain
	SubjectSPIFFEID string // optional: specific workload or node
}

// IsZero returns true if the scope is empty.
func (s PolicyScope) IsZero() bool {
	return s.TenantID == "" && s.EnvironmentID == "" && s.TrustDomain.IsZero() && s.SubjectSPIFFEID == ""
}

// Validate checks the scope for validity.
func (s PolicyScope) Validate() error {
	if s.TenantID == "" {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidScope)
	}
	if s.EnvironmentID == "" {
		return fmt.Errorf("%w: environment_id is required", ErrInvalidScope)
	}
	if s.TrustDomain.IsZero() {
		return fmt.Errorf("%w: trust_domain is required", ErrInvalidScope)
	}
	if s.SubjectSPIFFEID != "" {
		if _, err := spiffeid.FromString(s.SubjectSPIFFEID); err != nil {
			return fmt.Errorf("%w: invalid subject SPIFFE ID: %v", ErrInvalidScope, err)
		}
	}
	return nil
}

// Rule represents a single policy rule.
type Rule struct {
	ID          string                 `json:"id"`
	Effect      Effect                 `json:"effect"`
	Actions     []string               `json:"actions"`
	Resources   []string               `json:"resources"`
	Conditions  map[string]interface{} `json:"conditions,omitempty"`
	Explanation string                 `json:"explanation,omitempty"`
}

// Validate checks the rule for validity.
func (r Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("%w: rule id is required", ErrInvalidRule)
	}
	if r.Effect != EffectAllow && r.Effect != EffectDeny {
		return fmt.Errorf("%w: effect must be 'allow' or 'deny'", ErrInvalidRule)
	}
	if len(r.Actions) == 0 {
		return fmt.Errorf("%w: at least one action is required", ErrInvalidRule)
	}
	if len(r.Resources) == 0 {
		return fmt.Errorf("%w: at least one resource is required", ErrInvalidRule)
	}
	return nil
}

// Matches checks if the rule matches the given action and resource.
func (r Rule) Matches(action, resource string) bool {
	if !matchPattern(r.Actions, action) {
		return false
	}
	if !matchPattern(r.Resources, resource) {
		return false
	}
	return true
}

// matchPattern checks if any pattern in the list matches the value.
// Supports exact match and glob-style wildcards (*).
func matchPattern(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}

// Policy represents a versioned authorization policy.
type Policy struct {
	ID          string       `json:"id"`
	Version     int64        `json:"version"`
	Scope       PolicyScope  `json:"scope"`
	Rules       []Rule       `json:"rules"`
	Status      PolicyStatus `json:"status"`
	Approvers   []string     `json:"approvers,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	ActivatedAt *time.Time   `json:"activated_at,omitempty"`
	RevokedAt   *time.Time   `json:"revoked_at,omitempty"`
	Description string       `json:"description,omitempty"`
}

// PolicyStatus represents the lifecycle status of a policy.
type PolicyStatus string

const (
	PolicyStatusDraft     PolicyStatus = "draft"
	PolicyStatusPending   PolicyStatus = "pending"
	PolicyStatusActive    PolicyStatus = "active"
	PolicyStatusSuspended PolicyStatus = "suspended"
	PolicyStatusRevoked   PolicyStatus = "revoked"
)

// Validate checks the policy for validity.
func (p Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("%w: policy id is required", ErrInvalidPolicy)
	}
	if p.Version <= 0 {
		return fmt.Errorf("%w: version must be positive", ErrInvalidPolicy)
	}
	if err := p.Scope.Validate(); err != nil {
		return err
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: at least one rule is required", ErrInvalidPolicy)
	}
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("%w: rule %d: %v", ErrInvalidPolicy, i, err)
		}
	}
	if p.Status != PolicyStatusDraft && p.Status != PolicyStatusPending &&
		p.Status != PolicyStatusActive && p.Status != PolicyStatusSuspended &&
		p.Status != PolicyStatusRevoked {
		return fmt.Errorf("%w: invalid status: %s", ErrInvalidPolicy, p.Status)
	}
	return nil
}

// IsActive returns true if the policy is active and can be used for decisions.
func (p Policy) IsActive() bool {
	return p.Status == PolicyStatusActive && p.ActivatedAt != nil && !p.ActivatedAt.IsZero()
}

// Evaluate evaluates the policy against an authorization request.
// Returns the decision and the matching rule (if any).
func (p Policy) Evaluate(request AuthorizationRequest) (Decision, *Rule) {
	// Default deny
	decision := DecisionDeny
	var matchedRule *Rule

	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.Matches(request.Action, request.Resource) {
			if !rule.EvaluateDSL(request) {
				continue
			}
			matchedRule = rule
			if rule.Effect == EffectDeny {
				return DecisionDeny, rule
			}
			if rule.Effect == EffectAllow {
				decision = DecisionAllow
			}
		}
	}
	return decision, matchedRule
}

// AuthorizationRequest represents an authorization decision request.
type AuthorizationRequest struct {
	RequestID      string                 `json:"request_id"`
	Timestamp      time.Time              `json:"timestamp"`
	SubjectSPIFFEID string                `json:"subject_spiffe_id"`
	Action         string                 `json:"action"`
	Resource       string                 `json:"resource"`
	Method         string                 `json:"method,omitempty"`
	Path           string                 `json:"path,omitempty"`
	Audience       string                 `json:"audience,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	TraceID        string                 `json:"trace_id,omitempty"`
	CorrelationID  string                 `json:"correlation_id,omitempty"`
}

// Validate checks the request for validity.
func (r AuthorizationRequest) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidDecision)
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidDecision)
	}
	if _, err := spiffeid.FromString(r.SubjectSPIFFEID); err != nil {
		return fmt.Errorf("%w: invalid subject SPIFFE ID: %v", ErrInvalidDecision, err)
	}
	if r.Action == "" {
		return fmt.Errorf("%w: action is required", ErrInvalidDecision)
	}
	if r.Resource == "" {
		return fmt.Errorf("%w: resource is required", ErrInvalidDecision)
	}
	return nil
}

// AuthorizationDecision represents the result of an authorization decision.
type AuthorizationDecision struct {
	RequestID      string          `json:"request_id"`
	Decision       Decision        `json:"decision"`
	PolicyID       string          `json:"policy_id,omitempty"`
	PolicyVersion  int64           `json:"policy_version,omitempty"`
	MatchedRule    *Rule           `json:"matched_rule,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	EvaluatedAt    time.Time       `json:"evaluated_at"`
	CacheHit       bool            `json:"cache_hit"`
	Explanation    json.RawMessage `json:"explanation,omitempty"`
	TraceID        string          `json:"trace_id,omitempty"`
	CorrelationID  string          `json:"correlation_id,omitempty"`
}

// Validate checks the decision for validity.
func (d AuthorizationDecision) Validate() error {
	if d.RequestID == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidDecision)
	}
	if d.Decision != DecisionAllow && d.Decision != DecisionDeny {
		return fmt.Errorf("%w: decision must be 'allow' or 'deny'", ErrInvalidDecision)
	}
	if d.EvaluatedAt.IsZero() {
		return fmt.Errorf("%w: evaluated_at is required", ErrInvalidDecision)
	}
	return nil
}

// PolicyRevision represents a policy change for audit purposes.
type PolicyRevision struct {
	PolicyID       string          `json:"policy_id"`
	Version        int64           `json:"version"`
	Action         string          `json:"action"` // created, updated, activated, suspended, revoked
	Actor          string          `json:"actor"`
	PreviousStatus PolicyStatus    `json:"previous_status,omitempty"`
	NewStatus      PolicyStatus    `json:"new_status,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
	Changes        json.RawMessage `json:"changes,omitempty"`
}

// RiskSignal represents a risk signal from an external provider.
type RiskSignal struct {
	ProviderID string                 `json:"provider_id"`
	SignalID   string                 `json:"signal_id"`
	SubjectID  string                 `json:"subject_id"`
	Score      float64                `json:"score"` // 0.0 to 1.0
	Level      RiskLevel              `json:"level"`
	Evidence   map[string]interface{} `json:"evidence,omitempty"`
	ReceivedAt time.Time              `json:"received_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
}

// RiskLevel represents the risk level.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// Validate checks the risk signal for validity.
func (s RiskSignal) Validate() error {
	if s.ProviderID == "" {
		return fmt.Errorf("%w: provider_id is required", ErrInvalidPolicy)
	}
	if s.SignalID == "" {
		return fmt.Errorf("%w: signal_id is required", ErrInvalidPolicy)
	}
	if s.SubjectID == "" {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidPolicy)
	}
	if s.Score < 0 || s.Score > 1 {
		return fmt.Errorf("%w: score must be between 0 and 1", ErrInvalidPolicy)
	}
	if s.Level != RiskLevelLow && s.Level != RiskLevelMedium &&
		s.Level != RiskLevelHigh && s.Level != RiskLevelCritical {
		return fmt.Errorf("%w: invalid risk level: %s", ErrInvalidPolicy, s.Level)
	}
	if s.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: received_at is required", ErrInvalidPolicy)
	}
	return nil
}

// RiskProvider defines the interface for risk signal providers.
type RiskProvider interface {
	// GetSignals retrieves risk signals for a subject.
	GetSignals(ctx context.Context, subjectID string) ([]RiskSignal, error)
	// HealthCheck verifies the provider is healthy.
	HealthCheck(ctx context.Context) error
}

// PolicyDecisionCacheEntry represents a single cached decision.
type PolicyDecisionCacheEntry struct {
	RequestID       string
	PolicyID        string
	PolicyVersion   int64
	Decision        Decision
	EvaluatedAt     time.Time
	ExpiresAt       time.Time
	RiskScore       float64
	MatchedRule     string
	ContextHash     string
}

// PolicyDecisionCache manages cached authorization decisions with LRU eviction.
type PolicyDecisionCache struct {
	entries     map[string]PolicyDecisionCacheEntry
	tenantIndex map[string]map[string]PolicyDecisionCacheEntry
	order       []string
	maxSize     int
	entryTTL    time.Duration
	failClosed  []string
}

// NewPolicyDecisionCache creates a new cache with given size and TTL.
func NewPolicyDecisionCache(maxSize int, entryTTL time.Duration, failClosed []string) *PolicyDecisionCache {
	return &PolicyDecisionCache{
		entries:     make(map[string]PolicyDecisionCacheEntry),
		tenantIndex: make(map[string]map[string]PolicyDecisionCacheEntry),
		order:       make([]string, 0),
		maxSize:     maxSize,
		entryTTL:    entryTTL,
		failClosed:  failClosed,
	}
}

// Get retrieves a decision from the cache.
func (c *PolicyDecisionCache) Get(requestID string) (PolicyDecisionCacheEntry, bool) {
	entry, ok := c.entries[requestID]
	if !ok {
		return PolicyDecisionCacheEntry{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		return PolicyDecisionCacheEntry{}, false
	}
	return entry, true
}

// Set stores a decision in the cache.
func (c *PolicyDecisionCache) Set(entry PolicyDecisionCacheEntry) {
	c.entries[entry.RequestID] = entry
	c.order = append(c.order, entry.RequestID)
	if _, ok := c.tenantIndex[entry.PolicyID]; !ok {
		c.tenantIndex[entry.PolicyID] = make(map[string]PolicyDecisionCacheEntry)
	}
	c.tenantIndex[entry.PolicyID][entry.RequestID] = entry

	if len(c.order) > c.maxSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
		if tenantEntries, ok := c.tenantIndex[oldest]; ok {
			delete(tenantEntries, oldest)
			if len(tenantEntries) == 0 {
				delete(c.tenantIndex, oldest)
			}
		}
	}
}

// PurgeExpired removes expired entries from the cache.
func (c *PolicyDecisionCache) PurgeExpired() {
	now := time.Now()
	for reqID, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, reqID)
			if tenantEntries, ok := c.tenantIndex[reqID]; ok {
				delete(tenantEntries, reqID)
				if len(tenantEntries) == 0 {
					delete(c.tenantIndex, reqID)
				}
			}
			for i, orderReqID := range c.order {
				if orderReqID == reqID {
					c.order = append(c.order[:i], c.order[i+1:]...)
					break
				}
			}
		}
	}
}

// IsFailClosed reports whether the policy is marked as fail-closed.
func (c *PolicyDecisionCache) IsFailClosed(policyID string) bool {
	for _, pid := range c.failClosed {
		if pid == policyID {
			return true
		}
	}
	return false
}
