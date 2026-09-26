// Package registration stores server-side workload identity bindings.
package registration

import (
	"errors"
	"fmt"
	"sync"

	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	ErrInvalidRegistration = errors.New("registration: invalid registration")
	ErrNoMatch             = errors.New("registration: no registration matches attestation")
	ErrAmbiguous           = errors.New("registration: attestation matches multiple registrations")
	ErrInvalidState        = errors.New("registration: invalid lifecycle state")
)

const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
)

// Entry is an approved server-side binding from verified selectors to one
// workload identity. ID and trust-domain fields are never taken from a
// workload request.
type Entry struct {
	ID            string
	TenantID      string
	EnvironmentID string
	TrustDomain   spiffeid.TrustDomain
	WorkloadID    spiffeid.ID
	ParentAgentID spiffeid.ID
	Selectors     attestation.Selectors
	Status        string
}

type ChangeEvent struct {
	RegistrationID string
	Action         string
	Status         string
}

type AuditSink interface {
	RecordRegistrationChange(ChangeEvent) error
}

func (e Entry) validate() error {
	if e.ID == "" || e.TenantID == "" || e.EnvironmentID == "" || e.TrustDomain.IsZero() {
		return ErrInvalidRegistration
	}
	if e.Status != "" && e.Status != StatusActive && e.Status != StatusSuspended && e.Status != StatusRevoked {
		return ErrInvalidState
	}
	if !e.WorkloadID.IsWorkload() || !e.WorkloadID.MemberOf(e.TrustDomain) {
		return fmt.Errorf("%w: workload is outside the trust domain", ErrInvalidRegistration)
	}
	if !e.ParentAgentID.IsWorkload() {
		return fmt.Errorf("%w: parent agent must be a workload identity", ErrInvalidRegistration)
	}
	if len(e.Selectors) == 0 {
		return fmt.Errorf("%w: at least one selector is required", ErrInvalidRegistration)
	}
	for _, selector := range e.Selectors {
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
		}
	}
	return nil
}

// Registry is a concurrency-safe collection of approved registrations.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Entry
	audit   AuditSink
}

func New() *Registry { return &Registry{entries: make(map[string]Entry)} }

func (r *Registry) SetAuditSink(sink AuditSink) { r.mu.Lock(); defer r.mu.Unlock(); r.audit = sink }

// Put adds or replaces an entry by its administrative ID.
func (r *Registry) Put(entry Entry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	if entry.Status == "" {
		entry.Status = StatusActive
	}
	if r.entries == nil {
		r.entries = make(map[string]Entry)
	}
	r.entries[entry.ID] = entry
	audit := r.audit
	r.mu.Unlock()
	if audit != nil {
		if err := audit.RecordRegistrationChange(ChangeEvent{RegistrationID: entry.ID, Action: "put", Status: entry.Status}); err != nil {
			return err
		}
	}
	return nil
}

// Resolve matches only independently attested selectors. claimedID is
// deliberately absent: a caller cannot influence identity resolution by
// supplying a workload ID, tenant, or trust-domain claim.
func (r *Registry) Resolve(selectors attestation.Selectors) (Entry, error) {
	return r.resolve(selectors, spiffeid.ID{})
}

// ResolveForAgent matches verified selectors and the independently
// authenticated parent agent. The agent identity is a separate trust input;
// selectors alone must not let a workload claim a registration belonging to a
// different node.
func (r *Registry) ResolveForAgent(selectors attestation.Selectors, parentAgentID spiffeid.ID) (Entry, error) {
	if !parentAgentID.IsWorkload() {
		return Entry{}, ErrNoMatch
	}
	return r.resolve(selectors, parentAgentID)
}

func (r *Registry) resolve(selectors attestation.Selectors, parentAgentID spiffeid.ID) (Entry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var match Entry
	found := false
	for _, entry := range r.entries {
		if entry.Status != StatusActive {
			continue
		}
		if !parentAgentID.IsZero() && entry.ParentAgentID != parentAgentID {
			continue
		}
		if !selectors.Matches(entry.Selectors) {
			continue
		}
		if found {
			return Entry{}, ErrAmbiguous
		}
		match, found = entry, true
	}
	if !found {
		return Entry{}, ErrNoMatch
	}
	return match, nil
}

func (r *Registry) Suspend(id string) error { return r.setStatus(id, StatusSuspended) }

func (r *Registry) Revoke(id string) error { return r.setStatus(id, StatusRevoked) }

func (r *Registry) Activate(id string) error { return r.setStatus(id, StatusActive) }

func (r *Registry) setStatus(id, status string) error {
	r.mu.Lock()
	entry, ok := r.entries[id]
	if !ok {
		r.mu.Unlock()
		return ErrNoMatch
	}
	entry.Status = status
	r.entries[id] = entry
	audit := r.audit
	r.mu.Unlock()
	if audit != nil {
		return audit.RecordRegistrationChange(ChangeEvent{RegistrationID: id, Action: "status_change", Status: status})
	}
	return nil
}
