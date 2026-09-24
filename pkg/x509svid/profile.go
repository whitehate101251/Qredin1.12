package x509svid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// DefaultMinRSABits is the smallest RSA key Qredin accepts in an SVID chain.
const DefaultMinRSABits = 2048

// MaxClockSkew bounds how much notBefore leniency an operator may configure.
//
// Clock skew tolerance is a security relaxation with an availability
// justification, so it gets a ceiling. Five minutes is generous for any host
// running NTP; a host further out than that has a problem that widening this
// window will not fix, and the correct response is to fix the clock rather than
// to accept certificates that are not yet valid.
const MaxClockSkew = 5 * time.Minute

// Profile is the set of rules a certificate must satisfy to be accepted as part
// of an X.509-SVID chain.
//
// # Zero value
//
// The zero Profile is the strictest one. Every field that relaxes a rule is
// named Allow*, so a field an operator forgot to set, or a struct literal that
// a future refactor fails to populate, fails closed. There is deliberately no
// "Strict bool" that must be remembered.
//
// # Why the relaxations exist at all
//
// ADR 0002 commits Qredin to being stricter than go-spiffe in several places
// and never more permissive. Each of those strictnesses is a place where a
// conforming peer might nonetheless be rejected, so each gets an individually
// controllable escape hatch. An operator hitting an interoperability problem in
// production can relax exactly one rule, with the reason recorded in config,
// rather than reaching for a blanket "insecure" switch.
type Profile struct {
	// ClockSkew tolerates a verifier whose clock disagrees with the issuer's, so
	// that a freshly minted SVID is not rejected as not-yet-valid.
	//
	// The model is "the true time may be as late as now+ClockSkew". Every
	// certificate in the chain is judged against that later instant, which is
	// what makes a not-yet-valid certificate acceptable.
	//
	// Two consequences follow, and both are deliberate:
	//
	// Leniency applies to notBefore only. It never extends an expiry. Deciding
	// to keep trusting a credential its issuer has retired is not a clock
	// problem and must not be solved with a clock setting.
	//
	// The usable lifetime of a credential at this verifier is shortened by
	// ClockSkew, not lengthened: if the true time may be as late as
	// now+ClockSkew, then a certificate whose notAfter falls inside that window
	// may already have expired, and it is rejected. An operator who sets five
	// minutes of skew is choosing to lose the last five minutes of every SVID's
	// life. That is the correct direction to fail, and it is the reason
	// MaxClockSkew is small and the default is zero — rotation should be
	// bringing in a new SVID long before that window, and a deployment where it
	// matters has a rotation problem rather than a clock problem.
	ClockSkew time.Duration

	// MinRSABits is the smallest acceptable RSA modulus. Zero means
	// DefaultMinRSABits.
	MinRSABits int

	// AllowLeafWithoutBasicConstraints accepts a leaf that omits
	// basicConstraints. RFC 5280 treats an absent extension as cA=false, so
	// such a leaf is not a CA — but its issuer did not say so, and an SVID
	// issuer that omits the extension is one refactor away from omitting the
	// cA=false too.
	AllowLeafWithoutBasicConstraints bool

	// AllowLeafWithoutEKU accepts a leaf that declares neither clientAuth nor
	// serverAuth. Such a certificate is unusable for mTLS by any conforming
	// peer, so accepting it only hides a misconfiguration.
	AllowLeafWithoutEKU bool

	// AllowSigningCertTLSEKU accepts a CA certificate that also declares
	// clientAuth or serverAuth.
	//
	// Qredin rejects this by default because it means one key both mints
	// identities and terminates TLS connections: a signing key exposed to the
	// network surface is a signing key exposed to every bug in that surface.
	// Some third-party issuers do set these bits, which is why the escape hatch
	// exists.
	AllowSigningCertTLSEKU bool

	// AllowLeafWithoutDigitalSignature accepts a leaf whose keyUsage omits
	// digitalSignature.
	//
	// The SPIFFE X.509-SVID specification requires the bit, and a TLS
	// handshake using such a key is not authorised by its own certificate.
	// This exists only to unblock a peer with a broken issuer while it is
	// being fixed.
	AllowLeafWithoutDigitalSignature bool
}

// Validate reports whether the profile itself is usable.
//
// A bad profile is an operator error, not a peer error. It is caught once at
// startup so that it cannot show up later as a stream of verification failures
// that look like an attack.
func (p Profile) Validate() error {
	if p.ClockSkew < 0 {
		return newError(ReasonBadProfile, "clock skew must not be negative, got %v", p.ClockSkew)
	}
	if p.ClockSkew > MaxClockSkew {
		return newError(ReasonBadProfile, "clock skew %v exceeds the maximum of %v", p.ClockSkew, MaxClockSkew)
	}
	if p.MinRSABits != 0 && p.MinRSABits < DefaultMinRSABits {
		return newError(ReasonBadProfile, "minimum RSA size %d is below the floor of %d",
			p.MinRSABits, DefaultMinRSABits)
	}
	return nil
}

func (p Profile) minRSABits() int {
	if p.MinRSABits == 0 {
		return DefaultMinRSABits
	}
	return p.MinRSABits
}

// CheckLeaf applies the leaf X.509-SVID profile and returns the SPIFFE ID the
// certificate claims.
//
// Structural checks only: this says nothing about whether the certificate
// chains to a trusted authority or whether it is currently valid. Those are
// separate questions with separate failure modes, and keeping them separate is
// what lets an audit record say "the chain was fine but the leaf asserted
// cA=true" instead of a single opaque failure.
func (p Profile) CheckLeaf(cert *x509.Certificate) (spiffeid.ID, error) {
	id, err := IDFromCert(cert)
	if err != nil {
		return spiffeid.ID{}, err
	}

	// A path-less SPIFFE ID names the trust domain itself. That is the identity
	// of an authority, not of a caller, and a leaf bearing it would let a
	// workload authenticate as its own trust domain.
	if !id.IsWorkload() {
		return spiffeid.ID{}, newError(ReasonNoWorkloadPath,
			"leaf SVID must name a workload, but its SPIFFE ID has no path")
	}

	if cert.IsCA {
		return spiffeid.ID{}, newError(ReasonLeafIsCA,
			"leaf SVID asserts basicConstraints cA=true")
	}
	if !cert.BasicConstraintsValid && !p.AllowLeafWithoutBasicConstraints {
		return spiffeid.ID{}, newError(ReasonMissingBasicConstraints,
			"leaf SVID omits the basicConstraints extension")
	}

	// keyCertSign and cRLSign on a leaf are the bits that would turn a
	// compromised workload key into an issuer. crypto/x509 would also reject a
	// chain signed by such a certificate, but only once it was used; rejecting
	// the assertion itself means the certificate never becomes a credential.
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return spiffeid.ID{}, newError(ReasonForbiddenKeyUsage,
			"leaf SVID asserts keyCertSign or cRLSign")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 &&
		!p.AllowLeafWithoutDigitalSignature {
		return spiffeid.ID{}, newError(ReasonMissingDigitalSignature,
			"leaf SVID keyUsage omits digitalSignature")
	}
	if cert.KeyUsage == 0 && !p.AllowLeafWithoutDigitalSignature {
		// keyUsage absent entirely means "no restriction" under RFC 5280, but
		// the SPIFFE profile requires the bit to be asserted, and an absent
		// extension is indistinguishable from an issuer that forgot.
		return spiffeid.ID{}, newError(ReasonMissingDigitalSignature,
			"leaf SVID omits the keyUsage extension")
	}

	if !p.AllowLeafWithoutEKU && !hasAnyEKU(cert, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth) {
		return spiffeid.ID{}, newError(ReasonMissingEKU,
			"leaf SVID declares neither clientAuth nor serverAuth")
	}

	if err := p.checkPublicKey(cert); err != nil {
		return spiffeid.ID{}, err
	}
	return id, nil
}

// CheckSigningCert applies the profile for a certificate that signs others: an
// intermediate in a presented chain, or a root from the trust bundle.
//
// td is the trust domain the chain is being validated for. A signing
// certificate need not carry a URI SAN, but if it does, that SAN must be the
// trust domain's own ID — an intermediate claiming a different trust domain is
// the shape of a cross-domain confusion attack, and one claiming a workload
// path is an issuer that has confused a leaf for an authority.
func (p Profile) CheckSigningCert(cert *x509.Certificate, td spiffeid.TrustDomain) error {
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return newError(ReasonSigningCertNotCA,
			"signing certificate does not assert basicConstraints cA=true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return newError(ReasonSigningCertNoCertSign,
			"signing certificate keyUsage omits keyCertSign")
	}
	if !p.AllowSigningCertTLSEKU &&
		hasAnyEKU(cert, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth) {
		return newError(ReasonSigningCertHasTLSEKU,
			"signing certificate declares clientAuth or serverAuth; "+
				"set profile.allow_signing_cert_tls_eku to accept it")
	}

	uris, err := URISANs(cert)
	if err != nil {
		return &Error{Reason: ReasonMalformedSAN, err: err}
	}
	switch len(uris) {
	case 0:
		// Permitted: the SPIFFE specification does not require an authority to
		// name itself, and its trust domain is established by which bundle it
		// was found in.
	case 1:
		id, err := spiffeid.FromString(uris[0])
		if err != nil {
			return newError(ReasonSigningCertBadID,
				"signing certificate URI SAN is not a valid SPIFFE ID: %v", err)
		}
		if !id.MemberOf(td) {
			return newError(ReasonTrustDomainMismatch,
				"signing certificate belongs to trust domain %q, expected %q", id.TrustDomain(), td)
		}
		if id.IsWorkload() {
			return newError(ReasonSigningCertBadID,
				"signing certificate URI SAN has a workload path; an authority names its trust domain only")
		}
	default:
		return newError(ReasonMultipleURISANs,
			"signing certificate has %d URI SANs, at most one is permitted", len(uris))
	}

	return p.checkPublicKey(cert)
}

// checkValidity applies the certificate's validity window at the effective
// verification time.
//
// Both ends are tested against now+ClockSkew — the latest instant the true time
// may be, under the model described on Profile.ClockSkew. Applying the same
// instant to both ends is what makes the tolerance forgive a certificate that
// is not yet valid while refusing one that may already have expired. Testing
// notAfter at now instead would make the tolerance extend expiries, which is
// the one thing a clock setting must never do.
func (p Profile) checkValidity(cert *x509.Certificate, now time.Time) error {
	at := now.Add(p.ClockSkew)
	if at.Before(cert.NotBefore) {
		return newError(ReasonNotYetValid,
			"certificate is not valid until %s", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if at.After(cert.NotAfter) {
		return newError(ReasonExpired,
			"certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkPublicKey rejects key types and sizes Qredin will not accept.
//
// crypto/x509 will happily parse a P-224 certificate or a 512-bit RSA one, and
// crypto/tls will happily complete a handshake with it. The floor has to be
// applied somewhere, and applying it during SVID verification means it covers
// every entry point rather than every TLS listener.
func (p Profile) checkPublicKey(cert *x509.Certificate) error {
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return newError(ReasonUnsupportedKey, "unsupported elliptic curve")
		}
	case ed25519.PublicKey:
		return nil
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits < p.minRSABits() {
			return newError(ReasonUnsupportedKey, "RSA key is %d bits, minimum is %d", bits, p.minRSABits())
		}
		return nil
	default:
		// nil lands here too: crypto/x509 leaves PublicKey nil for algorithms
		// it does not recognise rather than failing to parse the certificate.
		return newError(ReasonUnsupportedKey, "unsupported public key type %T", cert.PublicKey)
	}
}

func hasAnyEKU(cert *x509.Certificate, want ...x509.ExtKeyUsage) bool {
	for _, have := range cert.ExtKeyUsage {
		if have == x509.ExtKeyUsageAny {
			return true
		}
		for _, w := range want {
			if have == w {
				return true
			}
		}
	}
	return false
}
