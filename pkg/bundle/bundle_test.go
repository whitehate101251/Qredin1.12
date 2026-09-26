package bundle_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	tdLocal   = spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	tdForeign = spiffeid.RequireTrustDomainFromString("partner.identity.example.net")
)

func TestMarshalParseRoundTrip(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	jwtKey := testsupport.NewKey(t)

	b := bundle.New(tdLocal)
	b.AddX509Authority(ca.Root())
	if err := b.AddJWTAuthority("key-1", jwtKey.Public()); err != nil {
		t.Fatal(err)
	}
	b.SetSequence(42)
	b.SetRefreshHint(300 * time.Second)

	doc, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := bundle.Parse(tdLocal, doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !got.Equal(b) {
		t.Error("round-tripped bundle is not equal to the original")
	}

	if seq, ok := got.Sequence(); !ok || seq != 42 {
		t.Errorf("Sequence() = %d, %v; want 42, true", seq, ok)
	}
	if hint, ok := got.RefreshHint(); !ok || hint != 300*time.Second {
		t.Errorf("RefreshHint() = %v, %v; want 5m, true", hint, ok)
	}

	// Determinism: a second marshal of an equal bundle must be byte-identical,
	// otherwise a bundle digest cannot be used as a change signal.
	doc2, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != string(doc2) {
		t.Errorf("marshal is not deterministic:\n %s\n %s", doc, doc2)
	}
}

// An absent refresh hint must stay absent rather than collapsing to zero, which
// would turn "no opinion" into "refresh continuously".
func TestRefreshHintAbsentVersusZero(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		b := mustParse(t, tdLocal, `{"keys":[]}`)
		if _, ok := b.RefreshHint(); ok {
			t.Error("absent spiffe_refresh_hint should report unset")
		}
		if got := b.RefreshHintOrDefault(); got != bundle.DefaultRefreshHint {
			t.Errorf("RefreshHintOrDefault() = %v, want %v", got, bundle.DefaultRefreshHint)
		}
	})

	t.Run("explicit zero", func(t *testing.T) {
		t.Parallel()
		b := mustParse(t, tdLocal, `{"spiffe_refresh_hint":0,"keys":[]}`)
		hint, ok := b.RefreshHint()
		if !ok {
			t.Fatal("explicit zero spiffe_refresh_hint should report set")
		}
		if hint != 0 {
			t.Errorf("RefreshHint() = %v, want 0", hint)
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		t.Parallel()
		_, err := bundle.Parse(tdLocal, []byte(`{"spiffe_refresh_hint":-1,"keys":[]}`))
		if !errors.Is(err, bundle.ErrMalformedBundle) {
			t.Errorf("error = %v, want ErrMalformedBundle", err)
		}
	})

	// time.Duration is a nanosecond int64. Without a bound, a hint near 2^63
	// seconds wraps to a negative duration, which a refresher reads as
	// "already due" and spins on.
	t.Run("absurdly large rejected", func(t *testing.T) {
		t.Parallel()
		_, err := bundle.Parse(tdLocal, []byte(`{"spiffe_refresh_hint":9223372036854775807,"keys":[]}`))
		if !errors.Is(err, bundle.ErrMalformedBundle) {
			t.Errorf("error = %v, want ErrMalformedBundle", err)
		}
	})

	// A bundle we would refuse to ingest must not be one we publish.
	t.Run("unpublishable hint fails marshal", func(t *testing.T) {
		t.Parallel()
		b := bundle.New(tdLocal)
		b.SetRefreshHint(365 * 24 * time.Hour)
		if _, err := b.Marshal(); err == nil {
			t.Error("marshalling an out-of-range refresh hint should fail")
		}
	})
}

// crypto/x509 parses certificates with unrecognised public key algorithms
// without error, leaving PublicKey nil, and it will happily parse a certificate
// carrying a key too weak to be an authority. Either would sit in the bundle
// looking trusted while being unable to verify anything.
func TestParseRejectsUnusableX509Authority(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "weak-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	doc := jwks(map[string]any{
		"use": "x509-svid",
		"x5c": []string{base64.StdEncoding.EncodeToString(der)},
	})
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := bundle.Parse(tdLocal, raw); !errors.Is(err, bundle.ErrMalformedBundle) {
		t.Errorf("Parse error = %v, want ErrMalformedBundle for a 1024-bit X.509 authority", err)
	}
}

func TestParseRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	certB64 := base64.StdEncoding.EncodeToString(ca.Root().Raw)
	jwtKey := testsupport.NewKey(t)
	ecJWK := ecJWKFields(t, jwtKey.Public())

	cases := []struct {
		name string
		doc  map[string]any
		want error
	}{
		{
			name: "missing use",
			doc:  jwks(map[string]any{"kty": "EC", "x5c": []string{certB64}}),
			want: bundle.ErrMalformedBundle,
		},
		{
			// kid identifies a JWT signing key. On an X.509 authority it
			// signals a producer conflating the two key types, and we would
			// rather fail loudly than guess which they meant.
			name: "x509 entry with kid",
			doc:  jwks(map[string]any{"use": "x509-svid", "kid": "k1", "x5c": []string{certB64}}),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "x509 entry with no x5c",
			doc:  jwks(map[string]any{"use": "x509-svid"}),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "x509 entry with two x5c elements",
			doc:  jwks(map[string]any{"use": "x509-svid", "x5c": []string{certB64, certB64}}),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "x509 entry with undecodable x5c",
			doc:  jwks(map[string]any{"use": "x509-svid", "x5c": []string{"!!!not base64!!!"}}),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "jwt entry without kid",
			doc:  jwks(merge(ecJWK, map[string]any{"use": "jwt-svid"})),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "jwt entry with empty kid",
			doc:  jwks(merge(ecJWK, map[string]any{"use": "jwt-svid", "kid": ""})),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "duplicate kid",
			doc: jwks(
				merge(ecJWK, map[string]any{"use": "jwt-svid", "kid": "same"}),
				merge(ecJWK, map[string]any{"use": "jwt-svid", "kid": "same"}),
			),
			want: bundle.ErrDuplicateKeyID,
		},
		{
			name: "unsupported kty",
			doc:  jwks(map[string]any{"use": "jwt-svid", "kid": "k1", "kty": "MAGIC"}),
			want: bundle.ErrMalformedBundle,
		},
		{
			name: "not json",
			doc:  nil,
			want: bundle.ErrMalformedBundle,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := []byte("this is not json")
			if tc.doc != nil {
				var err error
				raw, err = json.Marshal(tc.doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := bundle.Parse(tdLocal, raw); !errors.Is(err, tc.want) {
				t.Errorf("Parse error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A key whose advertised JWK parameters disagree with its x5c certificate is an
// internally inconsistent document. We cannot tell which the publisher meant,
// so we reject rather than silently trusting the certificate.
func TestParseRejectsKeyParameterMismatch(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	otherKey := testsupport.NewKey(t)

	doc := jwks(merge(ecJWKFields(t, otherKey.Public()), map[string]any{
		"use": "x509-svid",
		"x5c": []string{base64.StdEncoding.EncodeToString(ca.Root().Raw)},
	}))
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := bundle.Parse(tdLocal, raw); !errors.Is(err, bundle.ErrMalformedBundle) {
		t.Errorf("Parse error = %v, want ErrMalformedBundle", err)
	}
}

// Forward compatibility: a publisher introducing a new key type mid-rotation
// must not break existing consumers.
func TestParseIgnoresUnrecognisedUse(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	doc := jwks(
		map[string]any{"use": "x509-svid", "x5c": []string{base64.StdEncoding.EncodeToString(ca.Root().Raw)}},
		map[string]any{"use": "wit-svid", "kty": "EC", "kid": "future"},
	)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bundle.Parse(tdLocal, raw)
	if err != nil {
		t.Fatalf("unrecognised use should be skipped, not fatal: %v", err)
	}
	if got := len(b.X509Authorities()); got != 1 {
		t.Errorf("X509Authorities = %d, want 1", got)
	}
	if got := len(b.JWTAuthorities()); got != 0 {
		t.Errorf("JWTAuthorities = %d, want 0", got)
	}
}

func TestParseRejectsWeakAndInvalidKeys(t *testing.T) {
	t.Parallel()

	t.Run("rsa below minimum", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		doc := jwks(merge(rsaJWKFields(&key.PublicKey), map[string]any{"use": "jwt-svid", "kid": "weak"}))
		raw, _ := json.Marshal(doc)
		if _, err := bundle.Parse(tdLocal, raw); err == nil {
			t.Error("a 1024-bit RSA authority must be rejected")
		}
	})

	t.Run("ec point not on curve", func(t *testing.T) {
		t.Parallel()
		fields := ecJWKFields(t, testsupport.NewKey(t).Public())

		// Flip a byte in y so the point leaves the curve. An unvalidated point
		// is the entry point for invalid-curve attacks.
		y, err := base64.RawURLEncoding.DecodeString(fields["y"].(string))
		if err != nil {
			t.Fatal(err)
		}
		y[0] ^= 0xFF
		fields["y"] = base64.RawURLEncoding.EncodeToString(y)

		doc := jwks(merge(fields, map[string]any{"use": "jwt-svid", "kid": "bad-point"}))
		raw, _ := json.Marshal(doc)
		if _, err := bundle.Parse(tdLocal, raw); err == nil {
			t.Error("an EC point off the curve must be rejected")
		}
	})

	t.Run("ec coordinate wrong length", func(t *testing.T) {
		t.Parallel()
		fields := ecJWKFields(t, testsupport.NewKey(t).Public())
		x, _ := base64.RawURLEncoding.DecodeString(fields["x"].(string))
		fields["x"] = base64.RawURLEncoding.EncodeToString(x[1:]) // 31 bytes

		doc := jwks(merge(fields, map[string]any{"use": "jwt-svid", "kid": "short"}))
		raw, _ := json.Marshal(doc)
		if _, err := bundle.Parse(tdLocal, raw); err == nil {
			t.Error("a short EC coordinate must be rejected (RFC 7518 fixed length)")
		}
	})
}

// The Set API is the structural guard against pooled validation. These tests
// pin the behaviour the rest of the system depends on.
func TestSetIsolatesTrustDomains(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)
	set := bundle.NewSet(local.Bundle(), foreign.Bundle())

	t.Run("get returns only the named trust domain", func(t *testing.T) {
		t.Parallel()
		b, err := set.Get(tdLocal)
		if err != nil {
			t.Fatal(err)
		}
		if !b.HasX509Authority(local.Root()) {
			t.Error("local bundle missing its own authority")
		}
		if b.HasX509Authority(foreign.Root()) {
			t.Error("local bundle must not contain the foreign authority")
		}
	})

	t.Run("unknown trust domain is a hard failure", func(t *testing.T) {
		t.Parallel()
		unknown := spiffeid.RequireTrustDomainFromString("attacker.example")
		b, err := set.Get(unknown)
		if !errors.Is(err, bundle.ErrBundleNotFound) {
			t.Errorf("error = %v, want ErrBundleNotFound", err)
		}
		if b != nil {
			t.Error("no substitute bundle may be returned for an unknown trust domain")
		}
	})

	t.Run("zero trust domain rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := set.Get(spiffeid.TrustDomain{}); !errors.Is(err, bundle.ErrNoTrustDomain) {
			t.Errorf("error = %v, want ErrNoTrustDomain", err)
		}
	})
}

// X509Authorities must hand back a copy. If it returned the backing slice, a
// caller that only read the bundle could overwrite an entry in place and swap
// the authority a validator is about to trust.
func TestX509AuthoritiesReturnsCopy(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	b := local.Bundle()

	// In-place overwrite, not append: append would reallocate and pass even if
	// the backing array were shared.
	authorities := b.X509Authorities()
	if len(authorities) != 1 {
		t.Fatalf("fixture bundle has %d authorities, want 1", len(authorities))
	}
	authorities[0] = foreign.Root()

	if b.HasX509Authority(foreign.Root()) {
		t.Fatal("writing through the returned slice replaced the bundle's authority")
	}
	if !b.HasX509Authority(local.Root()) {
		t.Error("the bundle lost its own authority")
	}
}

// The same aliasing rule applies on the way in: a bundle must not keep a
// reference to a slice the caller can still write to.
func TestSetX509AuthoritiesCopiesInput(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	input := []*x509.Certificate{local.Root()}
	b := bundle.New(tdLocal)
	b.SetX509Authorities(input)

	input[0] = foreign.Root()

	if b.HasX509Authority(foreign.Root()) {
		t.Fatal("bundle aliased the caller's slice")
	}
	if !b.HasX509Authority(local.Root()) {
		t.Error("bundle lost the authority it was given")
	}
}

func TestApplyUpdateReportsAddedAndRemoved(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	set := bundle.NewSet(local.Bundle(), foreign.Bundle())

	// A complete response that omits the foreign trust domain means the
	// federation relationship ended. It must be withdrawn, not retained.
	added, removed := set.ApplyUpdate(bundle.NewSet(local.Bundle()))

	if len(added) != 0 {
		t.Errorf("added = %v, want none", added)
	}
	if len(removed) != 1 || removed[0] != tdForeign {
		t.Fatalf("removed = %v, want [%v]", removed, tdForeign)
	}
	if set.Has(tdForeign) {
		t.Error("omitted trust domain must be removed from the set")
	}
	if !set.Has(tdLocal) {
		t.Error("present trust domain must be retained")
	}
}

func TestSetRemoveIsRedaction(t *testing.T) {
	t.Parallel()

	foreign := testsupport.NewCA(t, tdForeign)
	set := bundle.NewSet(foreign.Bundle())

	set.Remove(tdForeign)

	if _, err := set.Get(tdForeign); !errors.Is(err, bundle.ErrBundleNotFound) {
		t.Errorf("after removal, Get error = %v, want ErrBundleNotFound", err)
	}
}

func TestCloneIsDeep(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	extra := testsupport.NewCA(t, tdLocal)

	original := local.Bundle()
	clone := original.Clone()

	clone.AddX509Authority(extra.Root())

	if original.HasX509Authority(extra.Root()) {
		t.Error("mutating a clone must not affect the original")
	}
	if !clone.HasX509Authority(extra.Root()) {
		t.Error("clone did not record its own mutation")
	}
}

// SetX509Authorities replaces rather than merges, because bundle refreshes are
// complete documents and a key absent from the new document must stop being
// trusted.
func TestSetX509AuthoritiesReplaces(t *testing.T) {
	t.Parallel()

	oldCA := testsupport.NewCA(t, tdLocal)
	newCA := testsupport.NewCA(t, tdLocal)

	b := oldCA.Bundle()
	b.SetX509Authorities([]*x509.Certificate{newCA.Root()})

	if b.HasX509Authority(oldCA.Root()) {
		t.Error("replaced authority is still trusted")
	}
	if !b.HasX509Authority(newCA.Root()) {
		t.Error("new authority is not trusted")
	}
}

func TestX509PoolRequiresAuthorities(t *testing.T) {
	t.Parallel()

	b := bundle.New(tdLocal)
	if _, err := b.X509Pool(); !errors.Is(err, bundle.ErrNoAuthorities) {
		t.Errorf("error = %v, want ErrNoAuthorities", err)
	}
}

func TestParseRequiresTrustDomain(t *testing.T) {
	t.Parallel()

	if _, err := bundle.Parse(spiffeid.TrustDomain{}, []byte(`{"keys":[]}`)); !errors.Is(err, bundle.ErrNoTrustDomain) {
		t.Errorf("error = %v, want ErrNoTrustDomain", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustParse(t *testing.T, td spiffeid.TrustDomain, doc string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Parse(td, []byte(doc))
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return b
}

func jwks(keys ...map[string]any) map[string]any {
	if keys == nil {
		keys = []map[string]any{}
	}
	return map[string]any{"keys": keys}
}

func merge(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func ecJWKFields(t *testing.T, pub crypto.PublicKey) map[string]any {
	t.Helper()
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	x := make([]byte, size)
	y := make([]byte, size)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)

	crv := map[elliptic.Curve]string{
		elliptic.P256(): "P-256",
		elliptic.P384(): "P-384",
		elliptic.P521(): "P-521",
	}[k.Curve]

	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

func rsaJWKFields(k *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
	}
}
