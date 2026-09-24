// Package bundle implements SPIFFE trust bundles.
//
// A trust bundle is the set of public keys a trust domain uses to sign SVIDs.
// Bundles are scoped to exactly one trust domain and stay associated with it
// for their whole lifetime.
//
// # Why the API looks like this
//
// The most consequential failure in an identity system of this shape is
// validating an SVID against a pool of certificates from several trust domains.
// If that happens, a certificate legitimately issued by trust domain A
// authenticates as an identity in trust domain B, and the trust boundary is
// gone. Plan §3.1 states the rule: select the bundle for the SVID's trust
// domain first, then validate against that bundle.
//
// Rather than document that rule and hope, this package makes the mistake
// unrepresentable:
//
//   - A Bundle is constructed with a trust domain and cannot be separated from
//     it. There is no constructor that takes bare certificates.
//   - Set has no method returning the union of its authorities. The only way to
//     obtain certificates is Set.Get(trustDomain), so a caller must name a
//     trust domain before it can obtain anything to verify against.
//   - Bundle.X509Authorities returns a copy, so a caller cannot append a
//     foreign authority into a bundle it merely read.
//
// Foreign (federated) bundles live in the same Set keyed by their own trust
// domain. They are never merged into the local bundle.
//
// Bundle and Set are safe for concurrent use. Bundles are mutated by the
// rotation and federation paths while being read by validators.
package bundle

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// DefaultRefreshHint is used when a bundle document omits spiffe_refresh_hint.
//
// The specification leaves the default to the consumer. Five minutes is chosen
// to bound how long a consumer can keep using a bundle after a key is removed
// following a compromise; it is a availability/latency trade and is
// configurable at the fetcher, not here.
const DefaultRefreshHint = 5 * time.Minute

// Errors returned by this package. Compare with errors.Is.
var (
	// ErrNoTrustDomain is returned when a bundle operation is attempted
	// without a trust domain. A bundle can never be trust-domain-less.
	ErrNoTrustDomain = errors.New("bundle: trust domain is required")

	// ErrTrustDomainMismatch is returned when a bundle is used for a trust
	// domain other than its own.
	ErrTrustDomainMismatch = errors.New("bundle: trust domain mismatch")

	// ErrBundleNotFound is returned by a Source when no bundle is configured
	// for the requested trust domain. This is the correct outcome for an
	// unknown or unfederated peer, and callers must treat it as a hard
	// authentication failure, never as "try another bundle".
	ErrBundleNotFound = errors.New("bundle: no bundle for trust domain")

	// ErrNoAuthorities is returned when a bundle contains no usable
	// authorities of the required type.
	ErrNoAuthorities = errors.New("bundle: no authorities")
)

// Bundle holds the X.509 and JWT authorities for a single trust domain, plus
// the sequence number and refresh hint carried by the bundle document.
type Bundle struct {
	td spiffeid.TrustDomain

	mu              sync.RWMutex
	x509Authorities []*x509.Certificate
	jwtAuthorities  map[string]crypto.PublicKey

	sequence       uint64
	sequenceSet    bool
	refreshHint    time.Duration
	refreshHintSet bool
}

// New returns an empty bundle for the given trust domain.
func New(td spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		td:             td,
		jwtAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromX509Authorities returns a bundle containing the given X.509 authorities.
func FromX509Authorities(td spiffeid.TrustDomain, authorities []*x509.Certificate) *Bundle {
	b := New(td)
	b.x509Authorities = copyCertificates(authorities)
	return b
}

// TrustDomain returns the trust domain this bundle represents. It is immutable.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain { return b.td }

// X509Authorities returns a copy of the bundle's X.509 authorities.
//
// A copy, not the backing slice: a validator that received the live slice could
// append to it and, by aliasing, inject an authority into a bundle it only had
// read access to.
func (b *Bundle) X509Authorities() []*x509.Certificate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return copyCertificates(b.x509Authorities)
}

// X509Pool returns the bundle's authorities as an *x509.CertPool for use with
// crypto/x509 chain building.
//
// The pool is built fresh on every call and contains authorities from this
// trust domain only. It must never be cached across trust domains or merged
// with another pool; doing so reintroduces exactly the pooled-validation bug
// this package exists to prevent.
func (b *Bundle) X509Pool() (*x509.CertPool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.x509Authorities) == 0 {
		return nil, fmt.Errorf("%w: trust domain %q has no X.509 authorities", ErrNoAuthorities, b.td)
	}
	pool := x509.NewCertPool()
	for _, c := range b.x509Authorities {
		pool.AddCert(c)
	}
	return pool, nil
}

// HasX509Authority reports whether the bundle contains the given certificate.
func (b *Bundle) HasX509Authority(c *x509.Certificate) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, have := range b.x509Authorities {
		if have.Equal(c) {
			return true
		}
	}
	return false
}

// AddX509Authority adds an X.509 authority. Adding an authority already present
// is a no-op, so repeated bundle refreshes do not grow the bundle.
func (b *Bundle) AddX509Authority(c *x509.Certificate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, have := range b.x509Authorities {
		if have.Equal(c) {
			return
		}
	}
	b.x509Authorities = append(b.x509Authorities, c)
}

// RemoveX509Authority removes an X.509 authority.
//
// Removal is how a compromised or retired key stops being trusted. Callers must
// respect the overlap rules in plan §3.7: remove only after every SVID signed
// by the key has expired, or immediately and deliberately in the compromise
// case, accepting that outstanding SVIDs stop validating.
func (b *Bundle) RemoveX509Authority(c *x509.Certificate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.x509Authorities[:0]
	for _, have := range b.x509Authorities {
		if !have.Equal(c) {
			out = append(out, have)
		}
	}
	// Clear the tail so removed certificates are not retained by the array.
	for i := len(out); i < len(b.x509Authorities); i++ {
		b.x509Authorities[i] = nil
	}
	b.x509Authorities = out
}

// SetX509Authorities replaces the X.509 authorities wholesale.
//
// Bundle refreshes are complete documents, never deltas, so replacement is the
// correct update primitive: a key absent from the new document must stop being
// trusted. Incremental addition would silently retain removed keys.
func (b *Bundle) SetX509Authorities(authorities []*x509.Certificate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509Authorities = copyCertificates(authorities)
}

// JWTAuthorities returns a copy of the bundle's JWT authorities keyed by key ID.
func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]crypto.PublicKey, len(b.jwtAuthorities))
	for k, v := range b.jwtAuthorities {
		out[k] = v
	}
	return out
}

// FindJWTAuthority returns the JWT authority with the given key ID.
//
// Lookup is by exact key ID. There is deliberately no "try every key" fallback:
// accepting a token because some key in the bundle happens to verify it defeats
// key rotation and makes a retired key indistinguishable from a current one.
func (b *Bundle) FindJWTAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.jwtAuthorities[keyID]
	return k, ok
}

// AddJWTAuthority adds or replaces a JWT authority. An empty key ID is rejected
// because a JWT-SVID cannot be routed to an unidentified key.
func (b *Bundle) AddJWTAuthority(keyID string, key crypto.PublicKey) error {
	if keyID == "" {
		return errors.New("bundle: JWT authority requires a non-empty key ID")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.jwtAuthorities == nil {
		b.jwtAuthorities = make(map[string]crypto.PublicKey)
	}
	b.jwtAuthorities[keyID] = key
	return nil
}

// RemoveJWTAuthority removes the JWT authority with the given key ID.
func (b *Bundle) RemoveJWTAuthority(keyID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.jwtAuthorities, keyID)
}

// SetJWTAuthorities replaces the JWT authorities wholesale. See
// SetX509Authorities for why replacement rather than merge.
func (b *Bundle) SetJWTAuthorities(authorities map[string]crypto.PublicKey) {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := make(map[string]crypto.PublicKey, len(authorities))
	for k, v := range authorities {
		next[k] = v
	}
	b.jwtAuthorities = next
}

// Sequence returns the bundle sequence number and whether one was set.
//
// The sequence number is monotonically increasing and exists to detect
// rollback: a fetched bundle whose sequence is lower than the one already held
// indicates a stale mirror, a cache-poisoning attempt, or a misconfigured
// endpoint. internal/federation treats a regression as an alertable security
// event and keeps the bundle it already has.
func (b *Bundle) Sequence() (uint64, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sequence, b.sequenceSet
}

// SetSequence sets the bundle sequence number.
func (b *Bundle) SetSequence(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sequence, b.sequenceSet = seq, true
}

// RefreshHint returns the publisher's suggested refresh interval and whether
// one was set. It is a hint: consumers may refresh more often, and must not
// treat it as a guarantee about key lifetime.
func (b *Bundle) RefreshHint() (time.Duration, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.refreshHint, b.refreshHintSet
}

// RefreshHintOrDefault returns the refresh hint, or DefaultRefreshHint if unset.
func (b *Bundle) RefreshHintOrDefault() time.Duration {
	if d, ok := b.RefreshHint(); ok {
		return d
	}
	return DefaultRefreshHint
}

// SetRefreshHint sets the refresh hint. Sub-second precision is discarded
// because the bundle document encodes the hint in whole seconds.
func (b *Bundle) SetRefreshHint(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshHint, b.refreshHintSet = d.Truncate(time.Second), true
}

// Empty reports whether the bundle contains no authorities of either type.
func (b *Bundle) Empty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.x509Authorities) == 0 && len(b.jwtAuthorities) == 0
}

// Clone returns a deep copy of the bundle.
//
// Used when handing a bundle to a Workload API stream: the stream must serve a
// stable snapshot, not a bundle that mutates mid-response under a rotation.
func (b *Bundle) Clone() *Bundle {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := &Bundle{
		td:              b.td,
		x509Authorities: copyCertificates(b.x509Authorities),
		jwtAuthorities:  make(map[string]crypto.PublicKey, len(b.jwtAuthorities)),
		sequence:        b.sequence,
		sequenceSet:     b.sequenceSet,
		refreshHint:     b.refreshHint,
		refreshHintSet:  b.refreshHintSet,
	}
	for k, v := range b.jwtAuthorities {
		out.jwtAuthorities[k] = v
	}
	return out
}

// Equal reports whether two bundles have the same trust domain and the same
// authorities. Sequence and refresh hint are ignored: this answers "would a
// consumer behave differently", which drives whether the Workload API needs to
// push an update, and a sequence bump with identical keys does not.
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}
	if b.td != other.td {
		return false
	}

	// Lock ordering: a bundle is never compared with itself under two locks,
	// but guard anyway so Equal(b, b) cannot deadlock.
	if b == other {
		return true
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	if len(b.x509Authorities) != len(other.x509Authorities) {
		return false
	}
	for i := range b.x509Authorities {
		if !b.x509Authorities[i].Equal(other.x509Authorities[i]) {
			return false
		}
	}
	if len(b.jwtAuthorities) != len(other.jwtAuthorities) {
		return false
	}
	for kid, key := range b.jwtAuthorities {
		otherKey, ok := other.jwtAuthorities[kid]
		if !ok || !publicKeysEqual(key, otherKey) {
			return false
		}
	}
	return true
}

func copyCertificates(in []*x509.Certificate) []*x509.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, len(in))
	copy(out, in)
	return out
}

// publicKeysEqual compares two public keys structurally.
//
// crypto.PublicKey is an empty interface, so this relies on the Equal method
// that every standard-library key type implements (Go 1.15+). An unknown key
// type without Equal compares unequal, which is the safe direction: the caller
// concludes the bundles differ and republishes, rather than concluding they
// match and skipping an update.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ae, ok := a.(equaler)
	if !ok {
		return false
	}
	return ae.Equal(b)
}
