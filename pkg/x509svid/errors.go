package x509svid

import (
	"errors"
	"fmt"
)

// Reason is a stable, machine-readable code describing why verification failed.
//
// Verification failures are security events, and a security event that can only
// be described by a free-text string cannot be counted, alerted on, or compared
// across releases. Every failure path in this package carries one of these
// codes; the audit record stores the code and the metrics pipeline labels on
// it, so "chain invalid" and "not federated with that trust domain" never blur
// into a single spike of "authentication failed".
//
// Reason values are part of Qredin's compatibility surface. They may be added
// to; existing values must not be renamed or repurposed.
type Reason string

const (
	// ReasonEmptyChain: no certificates were presented.
	ReasonEmptyChain Reason = "empty_chain"

	// ReasonMalformedSAN: the subjectAltName extension could not be parsed, was
	// present more than once, or contained a non-IA5 byte.
	ReasonMalformedSAN Reason = "malformed_san"

	// ReasonNoURISAN: the certificate carries no URI SAN, so it claims no
	// SPIFFE identity.
	ReasonNoURISAN Reason = "no_uri_san"

	// ReasonMultipleURISANs: more than one URI SAN. Which identity the
	// certificate asserts would depend on the verifier's choice.
	ReasonMultipleURISANs Reason = "multiple_uri_sans"

	// ReasonBadSPIFFEID: the URI SAN is not a valid SPIFFE ID.
	ReasonBadSPIFFEID Reason = "bad_spiffe_id"

	// ReasonNoWorkloadPath: the leaf's SPIFFE ID names a trust domain rather
	// than a workload. A path-less ID identifies an authority, not a caller.
	ReasonNoWorkloadPath Reason = "no_workload_path"

	// ReasonLeafIsCA: the leaf asserts cA=true, which would let the holder of a
	// workload key mint identities.
	ReasonLeafIsCA Reason = "leaf_is_ca"

	// ReasonMissingBasicConstraints: the leaf omits basicConstraints entirely.
	ReasonMissingBasicConstraints Reason = "missing_basic_constraints"

	// ReasonMissingDigitalSignature: keyUsage omits digitalSignature, so the key
	// is not authorised for the TLS handshake it is being presented for.
	ReasonMissingDigitalSignature Reason = "missing_digital_signature"

	// ReasonForbiddenKeyUsage: the leaf asserts keyCertSign or cRLSign.
	ReasonForbiddenKeyUsage Reason = "forbidden_key_usage"

	// ReasonMissingEKU: the leaf declares neither clientAuth nor serverAuth.
	ReasonMissingEKU Reason = "missing_eku"

	// ReasonSigningCertNotCA: a certificate used to sign in the chain does not
	// assert cA=true with basicConstraints marked valid.
	ReasonSigningCertNotCA Reason = "signing_cert_not_ca"

	// ReasonSigningCertNoCertSign: a signing certificate omits keyCertSign.
	ReasonSigningCertNoCertSign Reason = "signing_cert_no_cert_sign"

	// ReasonSigningCertHasTLSEKU: a signing certificate declares clientAuth or
	// serverAuth, making the same key usable both to sign identities and to
	// terminate TLS.
	ReasonSigningCertHasTLSEKU Reason = "signing_cert_has_tls_eku"

	// ReasonSigningCertBadID: a signing certificate carries a URI SAN that is
	// not its own trust domain's ID.
	ReasonSigningCertBadID Reason = "signing_cert_bad_id"

	// ReasonTrustDomainMismatch: a certificate in the chain belongs to a
	// different trust domain than the leaf.
	ReasonTrustDomainMismatch Reason = "trust_domain_mismatch"

	// ReasonNoBundle: no bundle is configured for the leaf's trust domain. For
	// a federated deployment this is the expected outcome for an unfederated
	// peer and must be treated as a hard failure, never as a reason to try
	// another bundle.
	ReasonNoBundle Reason = "no_bundle"

	// ReasonNoAuthorities: the bundle for the trust domain contains no X.509
	// authorities.
	ReasonNoAuthorities Reason = "no_authorities"

	// ReasonChainInvalid: the chain does not build to an authority in the
	// trust domain's bundle.
	ReasonChainInvalid Reason = "chain_invalid"

	// ReasonExpired: a certificate in the chain is past its notAfter.
	ReasonExpired Reason = "expired"

	// ReasonNotYetValid: a certificate in the chain is before its notBefore,
	// beyond the configured clock skew.
	ReasonNotYetValid Reason = "not_yet_valid"

	// ReasonUnsupportedKey: the certificate's public key algorithm or size is
	// not accepted.
	ReasonUnsupportedKey Reason = "unsupported_key"

	// ReasonBadProfile: the verifier was configured with an invalid profile.
	// This is an operator error, not a peer error, and is reported separately
	// so that a misconfiguration does not masquerade as an attack.
	ReasonBadProfile Reason = "bad_profile"
)

// Error is a verification failure.
//
// It deliberately does not carry the peer's certificate or SPIFFE ID in the
// message. Callers that need those for an audit record have them already; a
// failure message that interpolates attacker-controlled bytes ends up in logs,
// dashboards, and alert payloads.
type Error struct {
	Reason Reason
	err    error
}

func (e *Error) Error() string {
	if e.err == nil {
		return fmt.Sprintf("x509svid: %s", e.Reason)
	}
	return fmt.Sprintf("x509svid: %s: %v", e.Reason, e.err)
}

// Unwrap exposes the underlying cause for errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.err }

// newError builds a verification error with a formatted cause.
func newError(reason Reason, format string, args ...any) *Error {
	return &Error{Reason: reason, err: fmt.Errorf(format, args...)}
}

// ReasonOf returns the Reason carried by err, and whether err was a
// verification error at all.
//
// Audit and metrics code should use this rather than matching on message text.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}
