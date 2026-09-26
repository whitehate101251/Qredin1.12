// Package testsupport provides PKI fixtures for Qredin's tests.
//
// It builds certificate hierarchies, including deliberately malformed ones, so
// that the negative security tests required by plan §15.2 can be written
// against real DER rather than mocks. A validator tested only against
// hand-built structs is a validator that has never seen a certificate.
//
// # Why this cannot leak into production
//
// Every exported function takes a testing.TB. Production code has no way to
// obtain one, so this package is unusable outside a test binary — an
// enforcement mechanism rather than a comment asking nicely.
package testsupport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
)

// CA is a certificate authority fixture.
type CA struct {
	TrustDomain spiffeid.TrustDomain
	Cert        *x509.Certificate
	Key         crypto.Signer

	// chain is this CA's certificate followed by its ancestors, so an issued
	// SVID can carry the intermediates a verifier needs.
	chain []*x509.Certificate
}

// CertOption mutates a certificate template before signing.
//
// This is how the negative tests construct certificates that a conforming
// issuer would never produce: a leaf with CA=true, a leaf carrying two URI
// SANs, a certificate that expired yesterday. Being able to build invalid
// inputs is the whole point of the fixture.
type CertOption func(*x509.Certificate)

// NewCA returns a self-signed root CA for the trust domain.
func NewCA(tb testing.TB, td spiffeid.TrustDomain, opts ...CertOption) *CA {
	tb.Helper()

	key := NewKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: "qredin-test-root/" + td.Name()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{mustURL(tb, td.IDString())},
	}
	for _, opt := range opts {
		opt(tmpl)
	}

	cert := sign(tb, tmpl, tmpl, key.Public(), key)
	return &CA{TrustDomain: td, Cert: cert, Key: key, chain: []*x509.Certificate{cert}}
}

// Intermediate returns an intermediate CA signed by ca.
func (ca *CA) Intermediate(tb testing.TB, name string, opts ...CertOption) *CA {
	tb.Helper()

	key := NewKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{mustURL(tb, ca.TrustDomain.IDString())},
	}
	for _, opt := range opts {
		opt(tmpl)
	}

	cert := sign(tb, tmpl, ca.Cert, key.Public(), ca.Key)
	return &CA{
		TrustDomain: ca.TrustDomain,
		Cert:        cert,
		Key:         key,
		chain:       append([]*x509.Certificate{cert}, ca.chain...),
	}
}

// IssueSVID issues a leaf X.509-SVID for id, returning the chain (leaf first,
// then any intermediates) and the leaf's private key.
//
// The default template is a conforming leaf. Options are applied afterwards so
// a test can break exactly one property and assert that the validator notices
// that property specifically, rather than failing for an unrelated reason.
func (ca *CA) IssueSVID(tb testing.TB, id spiffeid.ID, opts ...CertOption) ([]*x509.Certificate, crypto.Signer) {
	tb.Helper()
	return ca.IssueSVIDWithKey(tb, id, NewKey(tb), opts...)
}

// IssueSVIDWithKey is IssueSVID with a caller-supplied leaf key, for tests that
// need a specific algorithm or size — a 1024-bit RSA leaf, say, to check that
// the key floor is enforced.
func (ca *CA) IssueSVIDWithKey(tb testing.TB, id spiffeid.ID, key crypto.Signer, opts ...CertOption) ([]*x509.Certificate, crypto.Signer) {
	tb.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:                  []*url.URL{mustURL(tb, id.String())},
	}
	for _, opt := range opts {
		opt(tmpl)
	}

	leaf := sign(tb, tmpl, ca.Cert, key.Public(), ca.Key)

	// The chain excludes the root: a verifier gets roots from the bundle, and
	// including one in the presented chain is how a caller accidentally tests
	// self-validation instead of bundle validation.
	chain := []*x509.Certificate{leaf}
	if len(ca.chain) > 1 {
		chain = append(chain, ca.chain[:len(ca.chain)-1]...)
	}
	return chain, key
}

// Bundle returns a bundle containing this CA's root certificate.
func (ca *CA) Bundle() *bundle.Bundle {
	root := ca.chain[len(ca.chain)-1]
	return bundle.FromX509Authorities(ca.TrustDomain, []*x509.Certificate{root})
}

// Root returns the root certificate of this CA's chain.
func (ca *CA) Root() *x509.Certificate { return ca.chain[len(ca.chain)-1] }

// NewKey returns a fresh P-256 signing key.
func NewKey(tb testing.TB) crypto.Signer {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating key: %v", err)
	}
	return key
}

// ---------------------------------------------------------------------------
// Certificate options for negative tests
// ---------------------------------------------------------------------------

// WithCAFlag sets basicConstraints CA. On a leaf this must be rejected.
func WithCAFlag() CertOption {
	return func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }
}

// WithKeyUsage replaces the key usage bits.
func WithKeyUsage(ku x509.KeyUsage) CertOption {
	return func(c *x509.Certificate) { c.KeyUsage = ku }
}

// WithExtKeyUsage replaces the extended key usages.
func WithExtKeyUsage(eku ...x509.ExtKeyUsage) CertOption {
	return func(c *x509.Certificate) { c.ExtKeyUsage = eku }
}

// WithURIs replaces the URI SANs. Use with zero or several URIs to test the
// "exactly one SPIFFE URI SAN" rule.
func WithURIs(tb testing.TB, uris ...string) CertOption {
	tb.Helper()
	parsed := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed = append(parsed, mustURL(tb, u))
	}
	return func(c *x509.Certificate) { c.URIs = parsed }
}

// WithNotBefore sets the start of the validity window.
func WithNotBefore(t time.Time) CertOption {
	return func(c *x509.Certificate) { c.NotBefore = t }
}

// WithNotAfter sets the end of the validity window.
func WithNotAfter(t time.Time) CertOption {
	return func(c *x509.Certificate) { c.NotAfter = t }
}

// Expired makes the certificate expired an hour ago.
func Expired() CertOption {
	return func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour)
	}
}

// NotYetValid makes the certificate valid starting an hour from now.
func NotYetValid() CertOption {
	return func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(time.Hour)
		c.NotAfter = time.Now().Add(2 * time.Hour)
	}
}

// WithDNSNames adds DNS SANs, which are permitted alongside the SPIFFE URI SAN.
func WithDNSNames(names ...string) CertOption {
	return func(c *x509.Certificate) { c.DNSNames = names }
}

// WithoutBasicConstraints omits the basicConstraints extension entirely.
//
// crypto/x509 emits the extension only when BasicConstraintsValid is set, so
// clearing the flag is how a test produces the certificate an issuer that
// forgot the extension would produce. RFC 5280 reads an absent extension as
// cA=false, which is why this is a separate, individually controllable
// relaxation rather than the same thing as asserting cA=false.
func WithoutBasicConstraints() CertOption {
	return func(c *x509.Certificate) { c.BasicConstraintsValid = false; c.IsCA = false }
}

// OIDSubjectAltName is id-ce-subjectAltName (RFC 5280 §4.2.1.6).
var OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// asn1TagURI is the context-specific tag of the uniformResourceIdentifier
// alternative of GeneralName.
const asn1TagURI = 6

// WithRawURISANs replaces the subjectAltName extension with one built from the
// given strings verbatim.
//
// crypto/x509 marshals URI SANs by calling (*url.URL).String(), so a test that
// goes through the URIs field can only produce SANs that net/url is willing to
// emit. That is exactly the set of inputs a URL-based parser handles correctly,
// which makes it useless for testing a parser that deliberately does not use
// net/url. This option writes the bytes directly, so a test can present an
// uppercase scheme, an embedded NUL, a percent escape, or any other encoding a
// hostile issuer might choose.
func WithRawURISANs(tb testing.TB, uris ...string) CertOption {
	tb.Helper()
	ext := RawSANExtension(tb, uris...)
	return func(c *x509.Certificate) {
		// Clear the fields crypto/x509 would use to synthesise its own SAN, or
		// the certificate ends up with two.
		c.URIs, c.DNSNames, c.EmailAddresses, c.IPAddresses = nil, nil, nil, nil
		c.ExtraExtensions = append(c.ExtraExtensions, ext)
	}
}

// WithDuplicateSANExtension gives the certificate two subjectAltName
// extensions, one naming each URI.
//
// RFC 5280 permits each extension at most once. A certificate with two is a way
// of showing one identity to a parser that takes the first match and a
// different one to a parser that takes the last, so the verifier must reject
// the certificate outright rather than pick.
//
// Both extensions are supplied explicitly because crypto/x509 suppresses its
// own generated SAN as soon as ExtraExtensions contains one.
func WithDuplicateSANExtension(tb testing.TB, first, second string) CertOption {
	tb.Helper()
	a := RawSANExtension(tb, first)
	b := RawSANExtension(tb, second)
	return func(c *x509.Certificate) {
		c.URIs, c.DNSNames, c.EmailAddresses, c.IPAddresses = nil, nil, nil, nil
		c.ExtraExtensions = append(c.ExtraExtensions, a, b)
	}
}

// RawSANExtension builds a subjectAltName extension whose
// uniformResourceIdentifier entries are the given strings verbatim.
//
// Exported so that a test can attach the extension to a certificate it builds
// itself, rather than one this package signs. Parsing tests need certificates
// carrying byte sequences that crypto/x509 would refuse to parse at all, and
// those cannot be produced by signing.
func RawSANExtension(tb testing.TB, uris ...string) pkix.Extension {
	tb.Helper()
	names := make([]asn1.RawValue, 0, len(uris))
	for _, u := range uris {
		names = append(names, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   asn1TagURI,
			Bytes: []byte(u),
		})
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		tb.Fatalf("marshalling subjectAltName: %v", err)
	}
	return pkix.Extension{Id: OIDSubjectAltName, Value: der}
}

func serial(tb testing.TB) *big.Int {
	tb.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		tb.Fatalf("generating serial: %v", err)
	}
	return n
}

func sign(tb testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	tb.Helper()
	// Go's parser rejects duplicate extension OIDs, so retain only the first
	// duplicate while creating the DER and restore the extra extension on the
	// parsed fixture below. This lets malformed-extension tests reach the
	// validator without weakening the production parser.
	createTemplate := *tmpl
	duplicateSAN := make([]pkix.Extension, 0, len(tmpl.ExtraExtensions))
	seenSAN := false
	createTemplate.ExtraExtensions = nil
	for _, ext := range tmpl.ExtraExtensions {
		if ext.Id.Equal(OIDSubjectAltName) {
			if seenSAN {
				duplicateSAN = append(duplicateSAN, ext)
				continue
			}
			seenSAN = true
		}
		createTemplate.ExtraExtensions = append(createTemplate.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, &createTemplate, parent, pub, signer)
	if err != nil {
		tb.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parsing created certificate: %v", err)
	}
	cert.Extensions = append(cert.Extensions, duplicateSAN...)
	return cert
}

func mustURL(tb testing.TB, s string) *url.URL {
	tb.Helper()
	// net/url is acceptable here because this is fixture construction, not
	// identity parsing. pkg/spiffeid deliberately avoids it; see that package's
	// documentation for why.
	u, err := url.Parse(s)
	if err != nil {
		tb.Fatalf("parsing URI %q: %v", s, err)
	}
	return u
}
