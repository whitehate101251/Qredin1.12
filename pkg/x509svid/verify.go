// Package x509svid implements the SPIFFE X.509-SVID profile: what a
// certificate must look like to carry a SPIFFE identity, and how one is
// verified.
//
// # The order of operations is the security property
//
// A verifier that builds a chain first and reads the identity afterwards has
// already made the mistake this package exists to prevent. If the chain is
// validated against a pool of authorities drawn from several trust domains,
// then a certificate legitimately issued by trust domain A will verify, and
// only later will anyone notice it claims an identity in trust domain B.
//
// Verification here runs in the opposite order, as plan §3.1 requires:
//
//  1. Read the SPIFFE ID out of the leaf's URI SAN. This is structural and
//     needs no trust.
//  2. Select the bundle for *that* trust domain. No bundle means the peer is
//     not federated with us, and that is a hard failure.
//  3. Build and validate the chain against that bundle only.
//  4. Re-apply the profile to every certificate in the resulting chain.
//
// pkg/bundle is shaped so that step 2 cannot be skipped: there is no way to
// obtain authorities without naming a trust domain first.
//
// # Relationship to go-spiffe
//
// ADR 0002 records why this is first-party code rather than a wrapper around
// go-spiffe, and commits Qredin to being stricter in specific, enumerated ways
// and never more permissive. Each strictness is an individually controllable
// field on Profile, and the zero Profile is the strict one.
//
// Workloads written against Qredin should use go-spiffe. This package exists
// for Qredin's own server, agent, and authorization plane, where the validation
// logic needs to be auditable line by line.
package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/clock"
	"github.com/qredin/qredin/pkg/spiffeid"
)

// Verifier validates X.509-SVID chains against per-trust-domain bundles.
//
// A Verifier is built once at startup, which is when its profile is validated,
// so a misconfiguration surfaces as a failed startup rather than as a stream of
// verification failures that look like an attack.
//
// Safe for concurrent use.
type Verifier struct {
	profile Profile
	source  bundle.Source
	clock   clock.Clock
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithProfile sets the certificate profile. The zero Profile, used when this
// option is omitted, is the strictest one.
func WithProfile(p Profile) Option {
	return func(v *Verifier) { v.profile = p }
}

// WithClock sets the time source. Tests use this to sit exactly on a validity
// boundary; production leaves it alone.
func WithClock(c clock.Clock) Option {
	return func(v *Verifier) { v.clock = c }
}

// NewVerifier returns a Verifier reading bundles from source.
//
// source must be a per-trust-domain source — typically a *bundle.Set fed by the
// agent's Workload API stream or the server's federation state. It is an
// interface so that the bundle it consults is always the current one rather
// than a snapshot taken at startup.
func NewVerifier(source bundle.Source, opts ...Option) (*Verifier, error) {
	if source == nil {
		return nil, errors.New("x509svid: a bundle source is required")
	}
	v := &Verifier{source: source, clock: clock.System()}
	for _, opt := range opts {
		opt(v)
	}
	if err := v.profile.Validate(); err != nil {
		return nil, err
	}
	v.clock = clock.OrSystem(v.clock)
	return v, nil
}

// Profile returns the verifier's profile.
func (v *Verifier) Profile() Profile { return v.profile }

// Verify validates an X.509-SVID chain and returns the SPIFFE ID it carries
// along with every chain that verified.
//
// chain is leaf-first, as presented in a TLS handshake. Certificates after the
// leaf are treated as candidate intermediates; a root smuggled in among them
// confers no trust, because roots come only from the bundle.
func (v *Verifier) Verify(chain []*x509.Certificate) (spiffeid.ID, [][]*x509.Certificate, error) {
	if len(chain) == 0 {
		return spiffeid.ID{}, nil, newError(ReasonEmptyChain, "no certificates presented")
	}
	leaf := chain[0]

	// Step 1: the identity is read before anything is trusted, because it
	// determines which bundle may be used to trust it.
	id, err := v.profile.CheckLeaf(leaf)
	if err != nil {
		return spiffeid.ID{}, nil, err
	}

	now := v.clock.Now()

	// Checked explicitly before chain building so that an expired SVID — by far
	// the most common failure in a healthy deployment — is reported as
	// "expired" and not as the generic "chain invalid" that crypto/x509 would
	// produce. Operators page on those two very differently.
	if err := v.profile.checkValidity(leaf, now); err != nil {
		return spiffeid.ID{}, nil, err
	}

	// Step 2: select the bundle for the leaf's trust domain, and only that one.
	td := id.TrustDomain()
	trustBundle, err := v.source.GetBundleForTrustDomain(td)
	if err != nil {
		if errors.Is(err, bundle.ErrBundleNotFound) {
			return spiffeid.ID{}, nil, newError(ReasonNoBundle,
				"no trust bundle for trust domain %q", td)
		}
		return spiffeid.ID{}, nil, newError(ReasonNoBundle,
			"looking up trust bundle for %q: %v", td, err)
	}
	roots, err := trustBundle.X509Pool()
	if err != nil {
		return spiffeid.ID{}, nil, newError(ReasonNoAuthorities,
			"trust domain %q has no usable X.509 authorities", td)
	}

	// Step 3: build the chain against that bundle.
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	candidates, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// The effective verification time is now+ClockSkew for every
		// certificate in the chain: the latest instant the true time may be.
		// See Profile.ClockSkew. Profile.checkValidity uses the same instant,
		// so the two agree rather than one quietly overriding the other.
		CurrentTime: now.Add(v.profile.ClockSkew),
		// crypto/x509 defaults to requiring serverAuth, which would reject a
		// client-only SVID. EKU is part of the SPIFFE profile and is enforced
		// by Profile.CheckLeaf and Profile.CheckSigningCert, where the rule can
		// be stated in SPIFFE's terms rather than the web PKI's.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return spiffeid.ID{}, nil, v.chainError(err, td, chain, now)
	}

	// Step 4: the profile applies to the whole chain, not just the leaf. An
	// intermediate that is not a CA, or that belongs to another trust domain,
	// invalidates the chain even though crypto/x509 accepted it.
	var (
		conforming [][]*x509.Certificate
		lastErr    error
	)
	for _, candidate := range candidates {
		if err := v.checkChain(candidate, td, now); err != nil {
			lastErr = err
			continue
		}
		conforming = append(conforming, candidate)
	}
	if len(conforming) == 0 {
		if lastErr == nil {
			// Defensive: crypto/x509 does not return an empty chain list
			// without an error, but a nil error here would be reported as a
			// successful verification.
			lastErr = newError(ReasonChainInvalid, "no chain satisfied the SVID profile")
		}
		return spiffeid.ID{}, nil, lastErr
	}

	return id, conforming, nil
}

// VerifyRaw parses DER-encoded certificates, leaf first, and verifies them.
//
// This is the entry point for a TLS VerifyPeerCertificate callback, which is
// handed raw DER precisely so that the application can decide what "valid"
// means rather than inheriting the web PKI's answer.
func (v *Verifier) VerifyRaw(rawCerts [][]byte) (spiffeid.ID, [][]*x509.Certificate, error) {
	chain, err := ParseChain(rawCerts)
	if err != nil {
		return spiffeid.ID{}, nil, err
	}
	return v.Verify(chain)
}

// checkChain applies the profile to a chain crypto/x509 has already accepted.
func (v *Verifier) checkChain(chain []*x509.Certificate, td spiffeid.TrustDomain, now time.Time) error {
	for i, cert := range chain {
		// Defence in depth. crypto/x509 was given the same effective time and
		// has already rejected anything outside its window, so this should
		// never fire. It is cheap, and it means an expired certificate cannot
		// be accepted by way of a change in how crypto/x509 interprets
		// CurrentTime.
		if err := v.profile.checkValidity(cert, now); err != nil {
			return fmt.Errorf("at depth %d: %w", i, err)
		}
		if i == 0 {
			continue // the leaf's profile was checked before the bundle was consulted
		}
		if err := v.profile.CheckSigningCert(cert, td); err != nil {
			return fmt.Errorf("at depth %d: %w", i, err)
		}
	}
	return nil
}

// ParseChain parses DER-encoded certificates, leaf first.
func ParseChain(rawCerts [][]byte) ([]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, newError(ReasonEmptyChain, "no certificates presented")
	}
	chain := make([]*x509.Certificate, 0, len(rawCerts))
	for i, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, newError(ReasonChainInvalid, "parsing certificate at depth %d: %v", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// chainError translates a crypto/x509 verification failure into a Qredin
// Reason.
//
// The distinction that matters operationally is "this peer is not one of ours"
// versus "this peer's certificate has a problem". Both arrive from crypto/x509
// as an error value, and collapsing them would make an expiry incident and a
// trust-boundary probe indistinguishable on a dashboard.
//
// presented is the chain as the peer sent it, used only to sharpen the
// diagnosis; see expiredPresentedIntermediate.
func (v *Verifier) chainError(err error, td spiffeid.TrustDomain, presented []*x509.Certificate, now time.Time) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		// crypto/x509 uses Expired for both ends of the validity window, and
		// returns this directly only for the leaf. The leaf's window was
		// already checked, so reaching here means it expired between that check
		// and this one, or sits inside the clock-skew window.
		return newError(ReasonExpired, "the leaf certificate is outside its validity window")
	}

	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		// An expired intermediate does not come back as CertificateInvalidError:
		// crypto/x509 records it as a hint on UnknownAuthorityError and exposes
		// neither the hint nor an Unwrap for it, so a stale intermediate would
		// otherwise be reported as an untrusted peer. Those two page different
		// people, so the presented chain is inspected directly.
		if timeErr := v.expiredPresentedIntermediate(presented, now); timeErr != nil {
			return timeErr
		}
		return newError(ReasonChainInvalid,
			"chain does not build to an authority in the bundle for %q", td)
	}

	return newError(ReasonChainInvalid, "chain verification failed: %v", err)
}

// expiredPresentedIntermediate reports a validity-window failure among the
// intermediates the peer presented, or nil if there is none.
//
// Only the peer's own certificates are examined. The bundle is deliberately not
// scanned: a bundle legitimately holds retired authorities during a rotation
// overlap, so an expired certificate there is normal and reporting it as the
// cause would send an operator after a healthy rotation instead of the real
// failure.
func (v *Verifier) expiredPresentedIntermediate(presented []*x509.Certificate, now time.Time) error {
	if len(presented) < 2 {
		return nil
	}
	for i, cert := range presented[1:] {
		if err := v.profile.checkValidity(cert, now); err != nil {
			return fmt.Errorf("presented intermediate at depth %d: %w", i+1, err)
		}
	}
	return nil
}
