package x509svid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/x509svid"
)

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

func TestParseRawRoundTrip(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, key := ca.IssueSVID(t, want)

	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	if svid.ID != want {
		t.Fatalf("ID = %q, want %q", svid.ID, want)
	}
	if len(svid.Certificates) != len(chain) {
		t.Fatalf("got %d certificates, want %d", len(svid.Certificates), len(chain))
	}
	if !svid.Leaf().Equal(chain[0]) {
		t.Error("Leaf() is not the first certificate of the presented chain")
	}

	gotDER, gotKeyDER, err := svid.MarshalRaw()
	assertNoError(t, err, "MarshalRaw")
	if string(gotDER) != string(certDER) {
		t.Error("MarshalRaw did not reproduce the certificate chain byte for byte")
	}
	if string(gotKeyDER) != string(keyDER) {
		t.Error("MarshalRaw did not reproduce the private key byte for byte")
	}
}

func TestParseRoundTrip(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate")

	want := workload(t, tdLocal, "/workload/api")
	chain, key := intermediate.IssueSVID(t, want)
	certDER, keyDER := rawMaterial(t, chain, key)

	original, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	certPEM, keyPEM, err := original.Marshal()
	assertNoError(t, err, "Marshal")

	reparsed, err := x509svid.Parse(certPEM, keyPEM)
	assertNoError(t, err, "Parse")

	if reparsed.ID != want {
		t.Fatalf("ID = %q, want %q", reparsed.ID, want)
	}
	// Chain order is load-bearing: a verifier treats element 0 as the leaf and
	// everything after it as a candidate intermediate. A round trip that
	// reordered the chain would turn an intermediate into the claimed identity.
	if len(reparsed.Certificates) != len(chain) {
		t.Fatalf("got %d certificates, want %d", len(reparsed.Certificates), len(chain))
	}
	for i := range chain {
		if !reparsed.Certificates[i].Equal(chain[i]) {
			t.Errorf("certificate at index %d does not match the original chain", i)
		}
	}
}

// TestParseIgnoresUnrelatedPEMBlocks covers the common operational layout in
// which the chain file also carries the trust bundle or a stray key.
func TestParseIgnoresUnrelatedPEMBlocks(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, key := ca.IssueSVID(t, want)
	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")
	certPEM, keyPEM, err := svid.Marshal()
	assertNoError(t, err, "Marshal")

	crl := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("not a crl")})
	dh := pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte("irrelevant")})

	// The chain sits between two blocks of other types, as it would in a file
	// that also carries the trust bundle.
	mixed := make([]byte, 0, len(crl)+len(certPEM)+len(dh))
	mixed = append(mixed, crl...)
	mixed = append(mixed, certPEM...)
	mixed = append(mixed, dh...)

	got, err := x509svid.Parse(mixed, keyPEM)
	assertNoError(t, err, "Parse with unrelated PEM blocks present")
	if got.ID != want {
		t.Fatalf("ID = %q, want %q", got.ID, want)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(got.Certificates))
	}
}

// ---------------------------------------------------------------------------
// The two invariants newSVID enforces
// ---------------------------------------------------------------------------

// TestParseRejectsAMismatchedKey covers a credential that authenticates as an
// identity its holder cannot actually use.
//
// Caught here it is a startup error naming the problem. Left uncaught it is a
// TLS handshake failure at the far end of a service mesh, reported by a peer
// that has no idea why.
func TestParseRejectsAMismatchedKey(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	other := testsupport.NewKey(t)
	certDER, keyDER := rawMaterial(t, chain, other)

	if _, err := x509svid.ParseRaw(certDER, keyDER); err == nil {
		t.Fatal("ParseRaw accepted a private key that does not match the leaf certificate")
	}
}

// TestParseRejectsALeafNamingATrustDomain is the issuance-side mirror of the
// verifier's rule.
//
// A workload must not be able to load a credential that names its own trust
// domain, even if some issuer were willing to mint one, because the process
// holding it would then present the identity of an authority on every outbound
// connection.
func TestParseRejectsALeafNamingATrustDomain(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, key := ca.IssueSVID(t, tdLocal.ID())
	certDER, keyDER := rawMaterial(t, chain, key)

	_, err := x509svid.ParseRaw(certDER, keyDER)
	assertReason(t, err, x509svid.ReasonNoWorkloadPath)
}

func TestParseRejectsALeafWithoutAUsableSPIFFEID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []testsupport.CertOption
		want x509svid.Reason
	}{
		{
			name: "no URI SAN",
			opts: []testsupport.CertOption{testsupport.WithURIs(t)},
			want: x509svid.ReasonNoURISAN,
		},
		{
			name: "two URI SANs",
			opts: []testsupport.CertOption{testsupport.WithURIs(t,
				"spiffe://prod.identity.example.com/workload/api",
				"spiffe://prod.identity.example.com/workload/admin")},
			want: x509svid.ReasonMultipleURISANs,
		},
		{
			name: "URI SAN is not a SPIFFE ID",
			opts: []testsupport.CertOption{testsupport.WithURIs(t, "https://prod.identity.example.com/x")},
			want: x509svid.ReasonBadSPIFFEID,
		},
	}

	ca := testsupport.NewCA(t, tdLocal)
	id := workload(t, tdLocal, "/workload/api")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, key := ca.IssueSVID(t, id, tc.opts...)
			certDER, keyDER := rawMaterial(t, chain, key)

			_, err := x509svid.ParseRaw(certDER, keyDER)
			assertReason(t, err, tc.want)
		})
	}
}

// TestParseDoesNotApplyTheFullProfile records a deliberate asymmetry between
// loading a credential and accepting one.
//
// An SVID is verified against a trust bundle by a Verifier. Repeating the
// profile here would mean that during an incident in which the profile has been
// relaxed — the reason every relaxation in Profile is individually controllable
// — a workload could not even load the credential it was issued. The two checks
// newSVID does keep are the ones that make the struct meaningful at all: the
// leaf names a workload, and the key matches the certificate.
func TestParseDoesNotApplyTheFullProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []testsupport.CertOption
	}{
		{
			name: "expired",
			opts: []testsupport.CertOption{testsupport.Expired()},
		},
		{
			name: "not yet valid",
			opts: []testsupport.CertOption{testsupport.NotYetValid()},
		},
		{
			name: "no clientAuth or serverAuth",
			opts: []testsupport.CertOption{testsupport.WithExtKeyUsage()},
		},
		{
			name: "keyUsage omits digitalSignature",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(x509.KeyUsageKeyEncipherment)},
		},
	}

	ca := testsupport.NewCA(t, tdLocal)
	id := workload(t, tdLocal, "/workload/api")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, key := ca.IssueSVID(t, id, tc.opts...)
			certDER, keyDER := rawMaterial(t, chain, key)

			svid, err := x509svid.ParseRaw(certDER, keyDER)
			assertNoError(t, err, "loading a credential that a Verifier would reject")

			// The Verifier is where that certificate stops being acceptable.
			if svid.ID != id {
				t.Fatalf("ID = %q, want %q", svid.ID, id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

// TestParseRawRejectsAnEmptyChain guards against a panic, not a bypass.
//
// x509.ParseCertificates returns an empty slice and a nil error for empty
// input, so without an explicit guard the leaf lookup indexes into nothing. A
// malformed Workload API response must not be able to crash the process holding
// the credential.
func TestParseRawRejectsAnEmptyChain(t *testing.T) {
	t.Parallel()

	key := testsupport.NewKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	assertNoError(t, err, "marshalling key")

	_, err = x509svid.ParseRaw(nil, keyDER)
	assertReason(t, err, x509svid.ReasonEmptyChain)

	_, err = x509svid.ParseRaw([]byte{}, keyDER)
	assertReason(t, err, x509svid.ReasonEmptyChain)
}

func TestParseRejectsMalformedMaterial(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, key := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"))
	certDER, keyDER := rawMaterial(t, chain, key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	t.Run("no CERTIFICATE blocks", func(t *testing.T) {
		t.Parallel()
		_, err := x509svid.Parse([]byte("not pem at all"), keyPEM)
		assertReason(t, err, x509svid.ReasonEmptyChain)
	})

	t.Run("a PEM file holding only the key", func(t *testing.T) {
		t.Parallel()
		_, err := x509svid.Parse(keyPEM, keyPEM)
		assertReason(t, err, x509svid.ReasonEmptyChain)
	})

	t.Run("CERTIFICATE block is not DER", func(t *testing.T) {
		t.Parallel()
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})
		if _, err := x509svid.Parse(bad, keyPEM); err == nil {
			t.Fatal("Parse accepted a CERTIFICATE block that is not a certificate")
		}
	})

	t.Run("no PEM block in the key", func(t *testing.T) {
		t.Parallel()
		if _, err := x509svid.Parse(certPEM, []byte("not pem at all")); err == nil {
			t.Fatal("Parse accepted key material with no PEM block")
		}
	})

	t.Run("key is not PKCS#8", func(t *testing.T) {
		t.Parallel()
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assertNoError(t, err, "generating key")
		sec1, err := x509.MarshalECPrivateKey(ec)
		assertNoError(t, err, "marshalling SEC 1 key")

		// SEC 1 rather than PKCS#8. The Workload API specifies PKCS#8, and
		// quietly accepting other encodings is how a loader ends up guessing.
		wrong := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sec1})
		if _, err := x509svid.Parse(certPEM, wrong); err == nil {
			t.Fatal("Parse accepted a key that is not PKCS#8")
		}
	})

	t.Run("certificate chain is not DER", func(t *testing.T) {
		t.Parallel()
		if _, err := x509svid.ParseRaw([]byte("nope"), keyDER); err == nil {
			t.Fatal("ParseRaw accepted a chain that is not DER")
		}
	})

	t.Run("raw key is not PKCS#8", func(t *testing.T) {
		t.Parallel()
		if _, err := x509svid.ParseRaw(certDER, []byte("nope")); err == nil {
			t.Fatal("ParseRaw accepted a key that is not PKCS#8")
		}
	})
}

// ---------------------------------------------------------------------------
// Keys that cannot be exported
// ---------------------------------------------------------------------------

// TestMarshalRefusesAnUnexportableKey covers the KMS and HSM case.
//
// PrivateKey is a crypto.Signer so that a key which can sign but cannot be
// exported is usable without a parallel code path. Marshalling such an SVID has
// to fail: the alternative is writing out a file that looks like a key and is
// not, which would be discovered at the next restart rather than now.
func TestMarshalRefusesAnUnexportableKey(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	id := workload(t, tdLocal, "/workload/api")
	chain, key := ca.IssueSVID(t, id)

	svid := &x509svid.SVID{ID: id, Certificates: chain, PrivateKey: remoteSigner{key}}

	if _, _, err := svid.MarshalRaw(); err == nil {
		t.Error("MarshalRaw exported a key that cannot be exported")
	}
	if _, _, err := svid.Marshal(); err == nil {
		t.Error("Marshal exported a key that cannot be exported")
	}

	// It remains fully usable for the thing it exists to do.
	tlsCert := svid.TLSCertificate()
	if tlsCert.PrivateKey == nil {
		t.Error("TLSCertificate dropped the private key")
	}
	if tlsCert.Leaf == nil || !tlsCert.Leaf.Equal(chain[0]) {
		t.Error("TLSCertificate did not carry the leaf")
	}
}

// ---------------------------------------------------------------------------
// The rest of the surface
// ---------------------------------------------------------------------------

func TestTLSCertificate(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate")
	chain, key := intermediate.IssueSVID(t, workload(t, tdLocal, "/workload/api"))
	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	got := svid.TLSCertificate()
	if len(got.Certificate) != len(chain) {
		t.Fatalf("got %d DER entries, want %d", len(got.Certificate), len(chain))
	}
	for i := range chain {
		if string(got.Certificate[i]) != string(chain[i].Raw) {
			t.Errorf("DER entry %d does not match the chain", i)
		}
	}
	// Populated so crypto/tls does not re-parse the DER on every handshake, and
	// so a caller inspecting the result sees the certificate this SVID was
	// built from rather than a second parse of the same bytes.
	if got.Leaf == nil {
		t.Fatal("Leaf was not populated")
	}
	if !got.Leaf.Equal(chain[0]) {
		t.Error("Leaf is not the chain's leaf certificate")
	}
	if got.PrivateKey == nil {
		t.Error("PrivateKey was not populated")
	}
}

func TestEmptySVID(t *testing.T) {
	t.Parallel()

	var svid x509svid.SVID

	if svid.Leaf() != nil {
		t.Error("Leaf() on an SVID with no certificates should be nil, not a panic or a zero value")
	}

	_, _, err := svid.MarshalRaw()
	assertReason(t, err, x509svid.ReasonEmptyChain)

	_, _, err = svid.Marshal()
	assertReason(t, err, x509svid.ReasonEmptyChain)
}

// TestHintIsNeverSetByParsing checks that the operator label stays out of the
// parse path.
//
// Hint is metadata the Workload API carries for the workload's own use. It is
// never an input to authentication or authorization, and it has no
// representation in a certificate — so a parsed SVID must not appear to have
// one.
func TestHintIsNeverSetByParsing(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, key := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"),
		testsupport.WithDNSNames("payments.svc.cluster.local"))
	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	if svid.Hint != "" {
		t.Fatalf("Hint = %q, want empty", svid.Hint)
	}
}

// TestIDIsDerivedFromTheCertificate is the plan §5 rule in test form: an
// identity is something a credential proves, not something its holder declares.
//
// The certificate here says two different things. Its subject common name — the
// field a pre-SPIFFE system would have read, and the field a fixture sets from
// whatever it was asked to issue for — names one workload. Its URI SAN, the only
// place a SPIFFE ID lives, names another. Only the SAN is an identity.
func TestIDIsDerivedFromTheCertificate(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)

	declared := workload(t, tdLocal, "/workload/admin")
	actual := workload(t, tdLocal, "/workload/api")

	chain, key := ca.IssueSVID(t, declared, testsupport.WithURIs(t, actual.String()))
	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	if got := chain[0].Subject.CommonName; got != declared.String() {
		t.Fatalf("fixture is no longer interesting: common name = %q, want %q", got, declared)
	}
	if svid.ID == declared {
		t.Fatal("the SVID took its identity from the subject common name")
	}
	if svid.ID != actual {
		t.Fatalf("ID = %q, want the URI SAN's value %q", svid.ID, actual)
	}
	if !svid.ID.MemberOf(tdLocal) {
		t.Fatalf("ID %q is not a member of %q", svid.ID, tdLocal)
	}
}

// TestParsedSVIDVerifies closes the loop between the two halves of this
// package: material a workload loaded is material a peer can verify.
func TestParsedSVIDVerifies(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, key := ca.IssueSVID(t, want)
	certDER, keyDER := rawMaterial(t, chain, key)

	svid, err := x509svid.ParseRaw(certDER, keyDER)
	assertNoError(t, err, "ParseRaw")

	tlsCert := svid.TLSCertificate()

	v := newVerifier(t, bundle.NewSet(ca.Bundle()))
	id, _, err := v.VerifyRaw(tlsCert.Certificate)
	assertNoError(t, err, "verifying the chain a TLS handshake would present")

	if id != want {
		t.Fatalf("ID = %q, want %q", id, want)
	}
	if id != svid.ID {
		t.Fatalf("the verifier read %q where the holder read %q", id, svid.ID)
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// rawMaterial renders a fixture chain and key into the Workload API's wire
// encoding: concatenated certificate DER, leaf first, and a PKCS#8 key.
func rawMaterial(t *testing.T, chain []*x509.Certificate, key crypto.Signer) (certDER, keyDER []byte) {
	t.Helper()
	for _, cert := range chain {
		certDER = append(certDER, cert.Raw...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}
	return certDER, keyDER
}

// remoteSigner stands in for a key held in a KMS or an HSM: it signs, and it
// cannot be exported. x509.MarshalPKCS8PrivateKey recognises only the stdlib
// key types, so wrapping one is enough to reproduce the behaviour.
type remoteSigner struct{ inner crypto.Signer }

func (s remoteSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s remoteSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}

var _ crypto.Signer = remoteSigner{}
