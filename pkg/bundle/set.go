package bundle

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// Source supplies the bundle for a trust domain.
//
// This is the only interface a validator should depend on, and its shape is the
// point: a caller must name a trust domain to get anything back. There is no
// "give me everything you trust" method, so the pooled-validation mistake
// cannot be expressed even by a careless caller.
//
// Implementations must return ErrBundleNotFound — never a substitute bundle,
// never an empty one — for a trust domain they do not know about.
type Source interface {
	GetBundleForTrustDomain(td spiffeid.TrustDomain) (*Bundle, error)
}

// SourceFunc adapts a function to Source.
type SourceFunc func(td spiffeid.TrustDomain) (*Bundle, error)

// GetBundleForTrustDomain implements Source.
func (f SourceFunc) GetBundleForTrustDomain(td spiffeid.TrustDomain) (*Bundle, error) {
	return f(td)
}

// Watcher receives bundle sets as they change.
//
// Updates carry the complete set, never a delta, matching Workload API
// semantics: a trust domain absent from an update has been withdrawn and must
// stop being trusted. A delta protocol cannot express withdrawal safely,
// because a dropped message becomes a silently retained trust relationship.
type Watcher interface {
	OnBundleSetUpdate(*Set)
}

// Set is a collection of bundles keyed by trust domain.
//
// A Set typically holds the local trust domain's bundle plus one bundle per
// federated foreign trust domain. Foreign bundles are stored beside the local
// one, never merged into it: merging would make a federated peer's authority
// indistinguishable from our own, and plan §3.7 forbids it.
//
// Safe for concurrent use.
type Set struct {
	mu      sync.RWMutex
	bundles map[spiffeid.TrustDomain]*Bundle
}

// NewSet returns a set containing the given bundles. A later bundle for the
// same trust domain replaces an earlier one.
func NewSet(bundles ...*Bundle) *Set {
	s := &Set{bundles: make(map[spiffeid.TrustDomain]*Bundle, len(bundles))}
	for _, b := range bundles {
		if b != nil {
			s.bundles[b.TrustDomain()] = b
		}
	}
	return s
}

// Get returns the bundle for the trust domain, or ErrBundleNotFound.
//
// ErrBundleNotFound is the expected outcome for an unfederated peer and must be
// treated as a hard authentication failure. It is never a reason to fall back
// to another bundle or to a system trust store.
func (s *Set) Get(td spiffeid.TrustDomain) (*Bundle, error) {
	if td.IsZero() {
		return nil, ErrNoTrustDomain
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.bundles[td]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBundleNotFound, td)
	}
	return b, nil
}

// GetBundleForTrustDomain implements Source.
func (s *Set) GetBundleForTrustDomain(td spiffeid.TrustDomain) (*Bundle, error) {
	return s.Get(td)
}

// Has reports whether the set contains a bundle for the trust domain.
func (s *Set) Has(td spiffeid.TrustDomain) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.bundles[td]
	return ok
}

// Add inserts or replaces the bundle for its trust domain.
func (s *Set) Add(b *Bundle) {
	if b == nil || b.TrustDomain().IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bundles == nil {
		s.bundles = make(map[spiffeid.TrustDomain]*Bundle)
	}
	s.bundles[b.TrustDomain()] = b
}

// Remove withdraws the bundle for a trust domain.
//
// This is the redaction primitive. When a Workload API response or a bundle
// refresh omits a trust domain that was previously present, the consumer must
// call Remove: the omission means the federation relationship ended, and
// keeping the bundle would keep authenticating a peer we no longer federate
// with. Plan §3.6 lists this under redaction handling.
func (s *Set) Remove(td spiffeid.TrustDomain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bundles, td)
}

// TrustDomains returns the trust domains in the set, sorted for deterministic
// iteration and reproducible diagnostics.
func (s *Set) TrustDomains() []spiffeid.TrustDomain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]spiffeid.TrustDomain, 0, len(s.bundles))
	for td := range s.bundles {
		out = append(out, td)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

// Len returns the number of bundles in the set.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bundles)
}

// Clone returns a deep copy of the set and every bundle in it.
func (s *Set) Clone() *Set {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := &Set{bundles: make(map[spiffeid.TrustDomain]*Bundle, len(s.bundles))}
	for td, b := range s.bundles {
		out.bundles[td] = b.Clone()
	}
	return out
}

// Equal reports whether two sets contain the same trust domains with equal
// bundles. Used to suppress no-op Workload API pushes.
func (s *Set) Equal(other *Set) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s == other {
		return true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	if len(s.bundles) != len(other.bundles) {
		return false
	}
	for td, b := range s.bundles {
		otherBundle, ok := other.bundles[td]
		if !ok || !b.Equal(otherBundle) {
			return false
		}
	}
	return true
}

// ApplyUpdate replaces the set's contents with next, returning the trust
// domains that were added and removed.
//
// This is the complete-response update primitive shared by the Workload API
// client and the federation refresher. Returning the removed domains gives the
// caller something concrete to audit and alert on — a silently vanishing
// federation relationship is exactly the kind of change that should never pass
// unnoticed.
func (s *Set) ApplyUpdate(next *Set) (added, removed []spiffeid.TrustDomain) {
	if next == nil {
		next = NewSet()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	next.mu.RLock()
	defer next.mu.RUnlock()

	if s.bundles == nil {
		s.bundles = make(map[spiffeid.TrustDomain]*Bundle, len(next.bundles))
	}

	for td := range s.bundles {
		if _, ok := next.bundles[td]; !ok {
			removed = append(removed, td)
		}
	}
	for td := range next.bundles {
		if _, ok := s.bundles[td]; !ok {
			added = append(added, td)
		}
	}

	replacement := make(map[spiffeid.TrustDomain]*Bundle, len(next.bundles))
	for td, b := range next.bundles {
		replacement[td] = b.Clone()
	}
	s.bundles = replacement

	sort.Slice(added, func(i, j int) bool { return added[i].Compare(added[j]) < 0 })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Compare(removed[j]) < 0 })
	return added, removed
}

// FetchResult reports the outcome of fetching a foreign bundle.
type FetchResult struct {
	Bundle           *Bundle
	SequenceAdvanced bool
	// SequenceRegressed is true when the fetched bundle's sequence number is
	// lower than the one already held. That indicates a stale mirror, a
	// rollback attempt, or a misconfigured endpoint, and the caller must keep
	// the bundle it has and raise a security alert (plan §9.5).
	SequenceRegressed bool
}

// Fetcher retrieves a foreign trust domain's bundle from its bundle endpoint.
// Implemented in internal/federation; declared here so that the bundle
// lifecycle types live with the bundle model.
type Fetcher interface {
	Fetch(ctx context.Context, td spiffeid.TrustDomain) (*FetchResult, error)
}
