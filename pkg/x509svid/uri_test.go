package x509svid_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

// The tests in this file work at two levels.
//
// The first set builds x509.Certificate values directly, attaching synthetic
// subjectAltName extensions. This is deliberate: crypto/x509 refuses to parse
// some of the byte sequences a hostile issuer can put in a SAN, and a test that
// can only produce certificates crypto/x509 accepts cannot check what happens
// when one slips through a future, more permissive parser. URISANs is written
// not to depend on crypto/x509 having filtered its input, and these tests are
// what hold it to that.
//
// The second set uses real signed certificates and shows the disagreement
// between cert.URIs and the raw DER. That disagreement is the reason this code
// exists.

// ---------------------------------------------------------------------------
// The DER walker
// ---------------------------------------------------------------------------

func TestURISANsReturnsRawBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sans []asn1.RawValue
		want []string
	}{
		{
			name: "single URI",
			sans: []asn1.RawValue{uriName("spiffe://example.org/workload/api")},
			want: []string{"spiffe://example.org/workload/api"},
		},
		{
			name: "two URIs are both returned, so the caller can reject the pair",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a"), uriName("spiffe://example.org/b")},
			want: []string{"spiffe://example.org/a", "spiffe://example.org/b"},
		},
		{
			name: "DNS SANs are skipped, not rejected",
			sans: []asn1.RawValue{dnsName("api.example.org"), uriName("spiffe://example.org/a"), dnsName("api.internal")},
			want: []string{"spiffe://example.org/a"},
		},
		{
			name: "no URI among other GeneralNames",
			sans: []asn1.RawValue{dnsName("api.example.org")},
			want: nil,
		},
		{
			name: "percent escapes are not decoded",
			sans: []asn1.RawValue{uriName("spiffe://example.org/workload%2Fapi")},
			want: []string{"spiffe://example.org/workload%2Fapi"},
		},
		{
			name: "scheme case is preserved",
			sans: []asn1.RawValue{uriName("SPIFFE://example.org/workload/api")},
			want: []string{"SPIFFE://example.org/workload/api"},
		},
		{
			name: "an embedded NUL is preserved rather than truncating the string",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a\x00/b")},
			want: []string{"spiffe://example.org/a\x00/b"},
		},
		{
			name: "dot segments are not resolved",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a/../b")},
			want: []string{"spiffe://example.org/a/../b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := certWithSANValues(generalNames(t, tc.sans...))
			got, err := x509svid.URISANs(cert)
			assertNoError(t, err, "URISANs")
			if len(got) != len(tc.want) {
				t.Fatalf("got %d URI SANs %q, want %d %q", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("URI SAN %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestURISANsRejectsMalformedExtensions(t *testing.T) {
	t.Parallel()

	valid := generalNames(t, uriName("spiffe://example.org/a"))

	tests := []struct {
		name string
		exts [][]byte
	}{
		{
			name: "two subjectAltName extensions",
			exts: [][]byte{valid, generalNames(t, uriName("spiffe://example.org/b"))},
		},
		{
			name: "two subjectAltName extensions with identical content",
			exts: [][]byte{valid, valid},
		},
		{
			name: "trailing data after the SEQUENCE",
			exts: [][]byte{append(append([]byte(nil), valid...), 0x00)},
		},
		{
			name: "extension value is not a SEQUENCE",
			exts: [][]byte{marshalValue(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: []byte("nope")})},
		},
		{
			name: "uniformResourceIdentifier marked compound",
			exts: [][]byte{generalNames(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, IsCompound: true, Bytes: []byte("spiffe://example.org/a")})},
		},
		{
			name: "uniformResourceIdentifier carries a non-IA5 byte",
			exts: [][]byte{generalNames(t, uriName("spiffe://example.org/caf\xc3\xa9"))},
		},
		{
			name: "GeneralName length runs past the end of the SEQUENCE",
			exts: [][]byte{{0x30, 0x05, 0x86, 0x0A, 'a', 'b', 'c'}},
		},
		{
			name: "empty extension value",
			exts: [][]byte{{}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := certWithSANValues(tc.exts...)

			if _, err := x509svid.URISANs(cert); err == nil {
				t.Fatal("URISANs accepted a malformed subjectAltName")
			}

			// Every parse failure must surface as one Reason. A malformed SAN
			// that reached the caller as ReasonBadSPIFFEID would be counted as
			// "peer sent a bad identity" when it is really "peer sent bytes we
			// could not parse" — a different incident.
			_, err := x509svid.IDFromCert(cert)
			assertReason(t, err, x509svid.ReasonMalformedSAN)
		})
	}
}

func TestURISANsAbsentExtension(t *testing.T) {
	t.Parallel()

	// No subjectAltName at all is not a parse error: it is a certificate that
	// claims no SPIFFE identity, which IDFromCert reports distinctly so that a
	// non-SPIFFE peer is not logged as having sent corrupt DER.
	uris, err := x509svid.URISANs(&x509.Certificate{})
	assertNoError(t, err, "URISANs on a certificate with no extensions")
	if uris != nil {
		t.Fatalf("got %q, want no URI SANs", uris)
	}

	_, err = x509svid.IDFromCert(&x509.Certificate{})
	assertReason(t, err, x509svid.ReasonNoURISAN)
}

func TestIDFromCertReasons(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sans []asn1.RawValue
		want x509svid.Reason
	}{
		{
			name: "no URI SAN",
			sans: []asn1.RawValue{dnsName("api.example.org")},
			want: x509svid.ReasonNoURISAN,
		},
		{
			name: "two URI SANs",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a"), uriName("spiffe://example.org/b")},
			want: x509svid.ReasonMultipleURISANs,
		},
		{
			name: "two URI SANs naming the same ID",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a"), uriName("spiffe://example.org/a")},
			want: x509svid.ReasonMultipleURISANs,
		},
		{
			name: "a SPIFFE URI beside a non-SPIFFE URI",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a"), uriName("https://example.org/a")},
			want: x509svid.ReasonMultipleURISANs,
		},
		{
			name: "not a SPIFFE URI",
			sans: []asn1.RawValue{uriName("https://example.org/workload")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "uppercase scheme",
			sans: []asn1.RawValue{uriName("SPIFFE://example.org/workload")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "uppercase trust domain",
			sans: []asn1.RawValue{uriName("spiffe://EXAMPLE.ORG/workload")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "percent-encoded path separator",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a%2Fb")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "embedded NUL",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a\x00b")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "userinfo in the authority",
			sans: []asn1.RawValue{uriName("spiffe://admin@example.org/workload")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "query string",
			sans: []asn1.RawValue{uriName("spiffe://example.org/workload?role=admin")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "fragment",
			sans: []asn1.RawValue{uriName("spiffe://example.org/workload#admin")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "dot segment",
			sans: []asn1.RawValue{uriName("spiffe://example.org/a/../b")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "trailing slash",
			sans: []asn1.RawValue{uriName("spiffe://example.org/workload/")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "empty string",
			sans: []asn1.RawValue{uriName("")},
			want: x509svid.ReasonBadSPIFFEID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := certWithSANValues(generalNames(t, tc.sans...))
			_, err := x509svid.IDFromCert(cert)
			assertReason(t, err, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// Real certificates, and the disagreement with cert.URIs
// ---------------------------------------------------------------------------

func TestIDFromCertOnAnIssuedSVID(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, _ := ca.IssueSVID(t, want)

	got, err := x509svid.IDFromCert(chain[0])
	assertNoError(t, err, "IDFromCert")
	if got != want {
		t.Fatalf("ID = %q, want %q", got, want)
	}
}

func TestIDFromCertAllowsDNSSANsAlongside(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, _ := ca.IssueSVID(t, want, testsupport.WithDNSNames("api.example.org", "api.internal"))

	got, err := x509svid.IDFromCert(chain[0])
	assertNoError(t, err, "IDFromCert with DNS SANs present")
	if got != want {
		t.Fatalf("ID = %q, want %q", got, want)
	}
}

// TestRawSANDisagreesWithParsedURI is the justification for this whole file.
//
// crypto/x509 hands back URI SANs as *url.URL, and net/url normalises what it
// parses. For each case below, the normalised view is a valid SPIFFE ID — or
// worse, a *different* valid SPIFFE ID — while the bytes actually signed by the
// issuer are not. A verifier reading cert.URIs would authorise an identity that
// does not appear in the certificate.
func TestRawSANDisagreesWithParsedURI(t *testing.T) {
	t.Parallel()

	t.Run("net/url lowercases the scheme", func(t *testing.T) {
		t.Parallel()

		ca := testsupport.NewCA(t, tdLocal)
		raw := "SPIFFE://prod.identity.example.com/workload/api"
		chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"),
			testsupport.WithRawURISANs(t, raw))
		cert := chain[0]

		// What crypto/x509 shows a caller.
		if len(cert.URIs) != 1 {
			t.Fatalf("fixture: cert.URIs has %d entries, want 1", len(cert.URIs))
		}
		normalised := cert.URIs[0].String()
		if normalised == raw {
			t.Fatalf("fixture is no longer interesting: net/url returned %q unchanged", raw)
		}
		if _, err := spiffeid.FromString(normalised); err != nil {
			t.Fatalf("fixture is no longer interesting: the normalised form %q is not a valid SPIFFE ID either: %v",
				normalised, err)
		}

		// What the certificate actually says.
		sans, err := x509svid.URISANs(cert)
		assertNoError(t, err, "URISANs")
		if len(sans) != 1 || sans[0] != raw {
			t.Fatalf("URISANs = %q, want exactly [%q]", sans, raw)
		}
		_, err = x509svid.IDFromCert(cert)
		assertReason(t, err, x509svid.ReasonBadSPIFFEID)
	})

	t.Run("net/url decodes percent escapes in Path", func(t *testing.T) {
		t.Parallel()

		ca := testsupport.NewCA(t, tdLocal)
		raw := "spiffe://prod.identity.example.com/workload%2Fapi"
		chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"),
			testsupport.WithRawURISANs(t, raw))
		cert := chain[0]

		if len(cert.URIs) != 1 {
			t.Fatalf("fixture: cert.URIs has %d entries, want 1", len(cert.URIs))
		}
		// cert.URIs[0].Path is the decoded form, and it is the field most code
		// reaches for. It spells a different workload than the one the issuer
		// signed: "/workload/api" rather than the single segment
		// "workload%2Fapi".
		if got, want := cert.URIs[0].Path, "/workload/api"; got != want {
			t.Fatalf("fixture is no longer interesting: url.Path = %q, want %q", got, want)
		}
		decoded := &url.URL{Scheme: cert.URIs[0].Scheme, Host: cert.URIs[0].Host, Path: cert.URIs[0].Path}
		if _, err := spiffeid.FromString(decoded.String()); err != nil {
			t.Fatalf("fixture is no longer interesting: decoded form is not a valid SPIFFE ID: %v", err)
		}

		sans, err := x509svid.URISANs(cert)
		assertNoError(t, err, "URISANs")
		if len(sans) != 1 || sans[0] != raw {
			t.Fatalf("URISANs = %q, want exactly [%q]", sans, raw)
		}
		_, err = x509svid.IDFromCert(cert)
		assertReason(t, err, x509svid.ReasonBadSPIFFEID)
	})
}

// TestDuplicateSANExtensionOnIssuedCertificate covers the shape where two
// parsers reading the same certificate see two different identities.
//
// crypto/x509 keeps the last subjectAltName extension it encounters and
// silently discards the first. Anything that takes the first — including a
// verifier in another language — sees the other identity. There is no safe way
// to choose, so the certificate is rejected.
func TestDuplicateSANExtensionOnIssuedCertificate(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"),
		testsupport.WithDuplicateSANExtension(t,
			"spiffe://prod.identity.example.com/workload/api",
			"spiffe://prod.identity.example.com/workload/admin"))

	if _, err := x509svid.URISANs(chain[0]); err == nil {
		t.Fatal("URISANs accepted a certificate with two subjectAltName extensions")
	}
	_, err := x509svid.IDFromCert(chain[0])
	assertReason(t, err, x509svid.ReasonMalformedSAN)
}

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

// certWithSANValues returns a certificate carrying one subjectAltName extension
// per supplied DER value.
//
// The certificate is not signed and could never be parsed from the wire. That
// is fine and intentional: URISANs reads cert.Extensions and nothing else, so
// this is the smallest input that exercises it, and it can carry bytes
// crypto/x509 would reject.
func certWithSANValues(values ...[]byte) *x509.Certificate {
	exts := make([]pkix.Extension, 0, len(values))
	for _, v := range values {
		exts = append(exts, pkix.Extension{Id: testsupport.OIDSubjectAltName, Value: v})
	}
	return &x509.Certificate{Extensions: exts}
}

func generalNames(t *testing.T, names ...asn1.RawValue) []byte {
	t.Helper()
	der, err := asn1.Marshal(names)
	if err != nil {
		t.Fatalf("marshalling GeneralNames: %v", err)
	}
	return der
}

func marshalValue(t *testing.T, v asn1.RawValue) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling ASN.1 value: %v", err)
	}
	return der
}

func uriName(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(s)}
}

func dnsName(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(s)}
}
