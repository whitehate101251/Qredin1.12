package x509svid_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

// ---------------------------------------------------------------------------
// The property this package exists for
// ---------------------------------------------------------------------------

// TestVerifyIsTrustDomainFirst is the headline test.
//
// A verifier that builds the chain first and reads the identity afterwards
// accepts the certificate built here: it is a genuine, correctly signed
// certificate from a trust domain we are federated with, and it chains to an
// authority we hold. The only thing wrong with it is that the identity it
// claims belongs to somebody else's trust domain.
//
// Pooling the authorities of both trust domains — the single most natural
// mistake in this code — makes this test pass the attacker's certificate.
func TestVerifyIsTrustDomainFirst(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	// Both bundles are present and both are valid. The federation relationship
	// is real; it is the claim that is not.
	set := bundle.NewSet(local.Bundle(), foreign.Bundle())
	v := newVerifier(t, set)

	t.Run("a federated peer cannot mint identities in our trust domain", func(t *testing.T) {
		impersonated := workload(t, tdLocal, "/workload/payments")
		chain, _ := foreign.IssueSVID(t, impersonated)

		id, _, err := v.Verify(chain)
		if err == nil {
			t.Fatalf("verified a certificate signed by %q that claims the identity %q",
				tdForeign, id)
		}
		assertReason(t, err, x509svid.ReasonChainInvalid)
	})

	t.Run("the same issuer is trusted for identities in its own trust domain", func(t *testing.T) {
		// Without this half, the test above would also pass if the foreign
		// bundle were simply missing or broken, which would prove nothing about
		// trust-domain selection.
		own := workload(t, tdForeign, "/workload/payments")
		chain, _ := foreign.IssueSVID(t, own)

		id, chains, err := v.Verify(chain)
		assertNoError(t, err, "verifying a foreign SVID against its own bundle")
		if id != own {
			t.Fatalf("ID = %q, want %q", id, own)
		}
		if len(chains) == 0 {
			t.Fatal("no verified chains returned")
		}
	})

	t.Run("our own issuer cannot mint identities in a federated trust domain", func(t *testing.T) {
		// The mirror image. Trust-domain isolation has to hold in the direction
		// that inconveniences us, not just the one that protects us.
		impersonated := workload(t, tdForeign, "/workload/payments")
		chain, _ := local.IssueSVID(t, impersonated)

		_, _, err := v.Verify(chain)
		assertReason(t, err, x509svid.ReasonChainInvalid)
	})
}

// TestVerifyRequiresABundleForTheLeafsTrustDomain covers the unfederated peer.
//
// This must be a hard failure and never a reason to try another bundle. An
// implementation that falls back to "any authority we happen to hold" turns
// every federation relationship into a relationship with every trust domain.
func TestVerifyRequiresABundleForTheLeafsTrustDomain(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	stranger := testsupport.NewCA(t, tdUnknown)

	v := newVerifier(t, bundle.NewSet(local.Bundle()))
	chain, _ := stranger.IssueSVID(t, workload(t, tdUnknown, "/workload/api"))

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoBundle)
}

func TestVerifyRequiresAuthoritiesInTheBundle(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)

	// A bundle that exists but is empty. This is the state an agent is in
	// between "the trust domain is configured" and "the first bundle has
	// arrived", and it must not be mistaken for "no checks required".
	v := newVerifier(t, bundle.NewSet(bundle.New(tdLocal)))
	chain, _ := local.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoAuthorities)
}

func TestVerifyRejectsAnUntrustedIssuerInTheSameTrustDomain(t *testing.T) {
	t.Parallel()

	trusted := testsupport.NewCA(t, tdLocal)
	rogue := testsupport.NewCA(t, tdLocal)

	v := newVerifier(t, bundle.NewSet(trusted.Bundle()))
	chain, _ := rogue.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonChainInvalid)
}

// TestVerifyIgnoresRootsSmuggledIntoTheChain checks that a peer cannot supply
// its own trust anchor.
//
// Everything after the leaf goes into the intermediates pool, never the roots
// pool. A verifier that added presented certificates to its roots would accept
// any self-signed certificate accompanied by a chain to itself, which is to say
// it would accept anything.
func TestVerifyIgnoresRootsSmuggledIntoTheChain(t *testing.T) {
	t.Parallel()

	trusted := testsupport.NewCA(t, tdLocal)
	rogue := testsupport.NewCA(t, tdLocal)

	v := newVerifier(t, bundle.NewSet(trusted.Bundle()))

	chain, _ := rogue.IssueSVID(t, workload(t, tdLocal, "/workload/api"))
	// The peer helpfully includes the root that would make its chain build.
	chain = append(chain, rogue.Root())

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonChainInvalid)
}

// ---------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------

func TestVerifyAcceptsAConformingSVID(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, _ := ca.IssueSVID(t, want)

	v := newVerifier(t, bundle.NewSet(ca.Bundle()))
	id, chains, err := v.Verify(chain)
	assertNoError(t, err, "Verify")

	if id != want {
		t.Fatalf("ID = %q, want %q", id, want)
	}
	if len(chains) != 1 {
		t.Fatalf("got %d verified chains, want 1", len(chains))
	}
	verified := chains[0]
	if len(verified) != 2 {
		t.Fatalf("verified chain has %d certificates, want 2 (leaf, root)", len(verified))
	}
	if !verified[0].Equal(chain[0]) {
		t.Error("the first certificate of the verified chain is not the presented leaf")
	}
	if !verified[len(verified)-1].Equal(ca.Root()) {
		t.Error("the verified chain does not terminate at the bundle's root")
	}
}

func TestVerifyAcceptsAChainThroughAnIntermediate(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate")

	want := workload(t, tdLocal, "/workload/api")
	chain, _ := intermediate.IssueSVID(t, want)
	if len(chain) != 2 {
		t.Fatalf("fixture: presented chain has %d certificates, want 2 (leaf, intermediate)", len(chain))
	}

	v := newVerifier(t, bundle.NewSet(root.Bundle()))
	id, chains, err := v.Verify(chain)
	assertNoError(t, err, "Verify")

	if id != want {
		t.Fatalf("ID = %q, want %q", id, want)
	}
	if len(chains[0]) != 3 {
		t.Fatalf("verified chain has %d certificates, want 3 (leaf, intermediate, root)", len(chains[0]))
	}
}

func TestVerifyAcceptsAClientOnlySVID(t *testing.T) {
	t.Parallel()

	// crypto/x509 defaults to requiring serverAuth. A workload that only ever
	// dials out has no reason to hold serverAuth, and rejecting it would push
	// operators to issue every SVID both usages.
	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/client"),
		testsupport.WithExtKeyUsage(x509.ExtKeyUsageClientAuth))

	v := newVerifier(t, bundle.NewSet(ca.Bundle()))
	_, _, err := v.Verify(chain)
	assertNoError(t, err, "verifying a client-only SVID")
}

func TestVerifyRaw(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := workload(t, tdLocal, "/workload/api")
	chain, _ := ca.IssueSVID(t, want)

	raw := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		raw = append(raw, cert.Raw)
	}

	v := newVerifier(t, bundle.NewSet(ca.Bundle()))
	id, _, err := v.VerifyRaw(raw)
	assertNoError(t, err, "VerifyRaw")
	if id != want {
		t.Fatalf("ID = %q, want %q", id, want)
	}
}

// ---------------------------------------------------------------------------
// Leaf profile — plan §15.2
// ---------------------------------------------------------------------------

func TestVerifyRejectsNonConformingLeaves(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []testsupport.CertOption
		want x509svid.Reason
	}{
		{
			name: "leaf asserts cA=true",
			opts: []testsupport.CertOption{testsupport.WithCAFlag()},
			want: x509svid.ReasonLeafIsCA,
		},
		{
			name: "leaf omits basicConstraints",
			opts: []testsupport.CertOption{testsupport.WithoutBasicConstraints()},
			want: x509svid.ReasonMissingBasicConstraints,
		},
		{
			name: "leaf asserts keyCertSign",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign)},
			want: x509svid.ReasonForbiddenKeyUsage,
		},
		{
			name: "leaf asserts cRLSign",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign)},
			want: x509svid.ReasonForbiddenKeyUsage,
		},
		{
			name: "leaf keyUsage omits digitalSignature",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(x509.KeyUsageKeyEncipherment)},
			want: x509svid.ReasonMissingDigitalSignature,
		},
		{
			name: "leaf omits keyUsage entirely",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(0)},
			want: x509svid.ReasonMissingDigitalSignature,
		},
		{
			name: "leaf declares neither clientAuth nor serverAuth",
			opts: []testsupport.CertOption{testsupport.WithExtKeyUsage()},
			want: x509svid.ReasonMissingEKU,
		},
		{
			name: "leaf declares an unrelated EKU only",
			opts: []testsupport.CertOption{testsupport.WithExtKeyUsage(x509.ExtKeyUsageCodeSigning)},
			want: x509svid.ReasonMissingEKU,
		},
		{
			name: "leaf has no URI SAN",
			opts: []testsupport.CertOption{testsupport.WithURIs(t)},
			want: x509svid.ReasonNoURISAN,
		},
		{
			name: "leaf has two URI SANs",
			opts: []testsupport.CertOption{testsupport.WithURIs(t,
				"spiffe://prod.identity.example.com/workload/api",
				"spiffe://prod.identity.example.com/workload/admin")},
			want: x509svid.ReasonMultipleURISANs,
		},
		{
			name: "leaf URI SAN is not a SPIFFE ID",
			opts: []testsupport.CertOption{testsupport.WithURIs(t, "https://prod.identity.example.com/workload/api")},
			want: x509svid.ReasonBadSPIFFEID,
		},
		{
			name: "leaf carries two subjectAltName extensions",
			opts: []testsupport.CertOption{testsupport.WithDuplicateSANExtension(t,
				"spiffe://prod.identity.example.com/workload/api",
				"spiffe://prod.identity.example.com/workload/admin")},
			want: x509svid.ReasonMalformedSAN,
		},
		{
			name: "leaf is expired",
			opts: []testsupport.CertOption{testsupport.Expired()},
			want: x509svid.ReasonExpired,
		},
		{
			name: "leaf is not yet valid",
			opts: []testsupport.CertOption{testsupport.NotYetValid()},
			want: x509svid.ReasonNotYetValid,
		},
	}

	ca := testsupport.NewCA(t, tdLocal)
	v := newVerifier(t, bundle.NewSet(ca.Bundle()))
	id := workload(t, tdLocal, "/workload/api")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, _ := ca.IssueSVID(t, id, tc.opts...)
			_, _, err := v.Verify(chain)
			assertReason(t, err, tc.want)
		})
	}
}

// TestVerifyRejectsALeafNamingATrustDomain covers the path-less SPIFFE ID.
//
// spiffe://example.org is the identity of the trust domain itself. A workload
// holding it would authenticate as its own certificate authority, which is a
// short walk from authorising itself for anything scoped to the domain.
func TestVerifyRejectsALeafNamingATrustDomain(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	v := newVerifier(t, bundle.NewSet(ca.Bundle()))

	chain, _ := ca.IssueSVID(t, tdLocal.ID())
	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoWorkloadPath)
}

func TestVerifyRejectsWeakKeys(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	id := workload(t, tdLocal, "/workload/api")

	t.Run("RSA below the floor", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		assertNoError(t, err, "generating a 1024-bit RSA key")

		chain, _ := ca.IssueSVIDWithKey(t, id, key)
		v := newVerifier(t, bundle.NewSet(ca.Bundle()))
		_, _, err = v.Verify(chain)
		assertReason(t, err, x509svid.ReasonUnsupportedKey)
	})

	t.Run("RSA at the floor is accepted", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, x509svid.DefaultMinRSABits)
		assertNoError(t, err, "generating a 2048-bit RSA key")

		chain, _ := ca.IssueSVIDWithKey(t, id, key)
		v := newVerifier(t, bundle.NewSet(ca.Bundle()))
		_, _, err = v.Verify(chain)
		assertNoError(t, err, "verifying an SVID with a 2048-bit RSA key")
	})

	t.Run("an operator may raise the floor above the default", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, x509svid.DefaultMinRSABits)
		assertNoError(t, err, "generating a 2048-bit RSA key")

		chain, _ := ca.IssueSVIDWithKey(t, id, key)
		v := newVerifier(t, bundle.NewSet(ca.Bundle()),
			x509svid.WithProfile(x509svid.Profile{MinRSABits: 3072}))
		_, _, err = v.Verify(chain)
		assertReason(t, err, x509svid.ReasonUnsupportedKey)
	})
}

// ---------------------------------------------------------------------------
// Signing-certificate profile
// ---------------------------------------------------------------------------

func TestVerifyRejectsNonConformingIntermediates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []testsupport.CertOption
		want x509svid.Reason
	}{
		{
			name: "intermediate also terminates TLS",
			opts: []testsupport.CertOption{testsupport.WithExtKeyUsage(x509.ExtKeyUsageServerAuth)},
			want: x509svid.ReasonSigningCertHasTLSEKU,
		},
		{
			name: "intermediate claims another trust domain",
			opts: []testsupport.CertOption{testsupport.WithURIs(t, tdForeign.IDString())},
			want: x509svid.ReasonTrustDomainMismatch,
		},
		{
			name: "intermediate claims a workload path",
			opts: []testsupport.CertOption{testsupport.WithURIs(t, "spiffe://prod.identity.example.com/workload/api")},
			want: x509svid.ReasonSigningCertBadID,
		},
		{
			name: "intermediate URI SAN is not a SPIFFE ID",
			opts: []testsupport.CertOption{testsupport.WithURIs(t, "https://prod.identity.example.com")},
			want: x509svid.ReasonSigningCertBadID,
		},
		{
			name: "intermediate has two URI SANs",
			opts: []testsupport.CertOption{testsupport.WithURIs(t,
				tdLocal.IDString(), tdForeign.IDString())},
			want: x509svid.ReasonMultipleURISANs,
		},
	}

	root := testsupport.NewCA(t, tdLocal)
	v := newVerifier(t, bundle.NewSet(root.Bundle()))
	id := workload(t, tdLocal, "/workload/api")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			intermediate := root.Intermediate(t, "qredin-test-intermediate", tc.opts...)
			chain, _ := intermediate.IssueSVID(t, id)
			_, _, err := v.Verify(chain)
			assertReason(t, err, tc.want)
		})
	}
}

// TestVerifyAcceptsAnIntermediateWithoutAURISAN records a deliberate
// permissiveness.
//
// The SPIFFE specification does not require a signing certificate to name its
// own trust domain, and a certificate's trust domain is established by which
// bundle it was found in rather than by what it says about itself. Requiring
// the SAN would reject conforming issuers, which ADR 0002 forbids.
func TestVerifyAcceptsAnIntermediateWithoutAURISAN(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate", testsupport.WithURIs(t))
	chain, _ := intermediate.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	v := newVerifier(t, bundle.NewSet(root.Bundle()))
	_, _, err := v.Verify(chain)
	assertNoError(t, err, "verifying through an intermediate with no URI SAN")
}

// TestVerifyReportsAnExpiredIntermediateAsExpired guards a diagnosis, not a
// decision.
//
// crypto/x509 reports an expired intermediate as an unknown authority: it
// records the real cause as an unexported hint and offers no way to read it.
// Left alone, a routine expiry during a CA rotation would page whoever owns
// federation as though an untrusted peer were probing the trust boundary.
func TestVerifyReportsAnExpiredIntermediateAsExpired(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate", testsupport.Expired())

	// The leaf itself is still within its window, so the only problem is the
	// intermediate.
	chain, _ := intermediate.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	v := newVerifier(t, bundle.NewSet(root.Bundle()))
	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonExpired)
}

// TestVerifyDoesNotBlameTheBundleForARotation is the other half of that
// diagnosis.
//
// A bundle legitimately holds a retired authority through the rotation overlap.
// If the expiry scan looked at the bundle rather than at what the peer
// presented, every untrusted-peer event during a rotation would be misreported
// as an expiry and sent to the wrong team.
func TestVerifyDoesNotBlameTheBundleForARotation(t *testing.T) {
	t.Parallel()

	current := testsupport.NewCA(t, tdLocal)
	retired := testsupport.NewCA(t, tdLocal, testsupport.Expired())
	rogue := testsupport.NewCA(t, tdLocal)

	// The bundle is mid-rotation: the retired authority is still published.
	b := bundle.FromX509Authorities(tdLocal, []*x509.Certificate{current.Root(), retired.Root()})
	v := newVerifier(t, bundle.NewSet(b))

	chain, _ := rogue.IssueSVID(t, workload(t, tdLocal, "/workload/api"))
	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonChainInvalid)
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

func TestVerifyValidityWindow(t *testing.T) {
	t.Parallel()

	// Pinned to the real clock because the CA fixtures build their own validity
	// windows around it. Everything below moves relative to this instant.
	base := time.Now()

	ca := testsupport.NewCA(t, tdLocal)
	set := bundle.NewSet(ca.Bundle())
	id := workload(t, tdLocal, "/workload/api")

	t.Run("an SVID expires when the clock passes notAfter", func(t *testing.T) {
		t.Parallel()

		chain, _ := ca.IssueSVID(t, id,
			testsupport.WithNotBefore(base.Add(-time.Minute)),
			testsupport.WithNotAfter(base.Add(10*time.Minute)))

		clk := testsupport.NewClock(t, base)
		v := newVerifier(t, set, x509svid.WithClock(clk))

		_, _, err := v.Verify(chain)
		assertNoError(t, err, "verifying inside the validity window")

		clk.Advance(11 * time.Minute)
		_, _, err = v.Verify(chain)
		assertReason(t, err, x509svid.ReasonExpired)
	})

	t.Run("clock skew forgives a not-yet-valid SVID", func(t *testing.T) {
		t.Parallel()

		// Two minutes in the future: inside a five-minute tolerance, outside a
		// zero one.
		chain, _ := ca.IssueSVID(t, id,
			testsupport.WithNotBefore(base.Add(2*time.Minute)),
			testsupport.WithNotAfter(base.Add(time.Hour)))

		clk := testsupport.NewClock(t, base)

		strict := newVerifier(t, set, x509svid.WithClock(clk))
		_, _, err := strict.Verify(chain)
		assertReason(t, err, x509svid.ReasonNotYetValid)

		tolerant := newVerifier(t, set,
			x509svid.WithClock(clk),
			x509svid.WithProfile(x509svid.Profile{ClockSkew: 5 * time.Minute}))
		_, _, err = tolerant.Verify(chain)
		assertNoError(t, err, "verifying a not-yet-valid SVID within the skew tolerance")
	})

	t.Run("clock skew never extends an expiry", func(t *testing.T) {
		t.Parallel()

		// Expired one minute ago. A tolerance that worked in both directions
		// would accept this.
		chain, _ := ca.IssueSVID(t, id,
			testsupport.WithNotBefore(base.Add(-time.Hour)),
			testsupport.WithNotAfter(base.Add(-time.Minute)))

		clk := testsupport.NewClock(t, base)
		v := newVerifier(t, set,
			x509svid.WithClock(clk),
			x509svid.WithProfile(x509svid.Profile{ClockSkew: x509svid.MaxClockSkew}))

		_, _, err := v.Verify(chain)
		assertReason(t, err, x509svid.ReasonExpired)
	})

	t.Run("clock skew shortens the usable lifetime rather than lengthening it", func(t *testing.T) {
		t.Parallel()

		// Expires in two minutes. Under the "the true time may be as late as
		// now+skew" model this may already have expired, so a verifier
		// configured with five minutes of tolerance refuses it. This is the
		// documented cost of the setting; the test exists so that the cost is a
		// decision on record rather than a surprise during an incident.
		chain, _ := ca.IssueSVID(t, id,
			testsupport.WithNotBefore(base.Add(-time.Hour)),
			testsupport.WithNotAfter(base.Add(2*time.Minute)))

		clk := testsupport.NewClock(t, base)

		strict := newVerifier(t, set, x509svid.WithClock(clk))
		_, _, err := strict.Verify(chain)
		assertNoError(t, err, "a verifier with no skew tolerance should still accept this SVID")

		tolerant := newVerifier(t, set,
			x509svid.WithClock(clk),
			x509svid.WithProfile(x509svid.Profile{ClockSkew: 5 * time.Minute}))
		_, _, err = tolerant.Verify(chain)
		assertReason(t, err, x509svid.ReasonExpired)
	})
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestNewVerifierRejectsBadConfiguration(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	set := bundle.NewSet(ca.Bundle())

	t.Run("no bundle source", func(t *testing.T) {
		t.Parallel()
		if _, err := x509svid.NewVerifier(nil); err == nil {
			t.Fatal("NewVerifier accepted a nil bundle source")
		}
	})

	tests := []struct {
		name string
		prof x509svid.Profile
	}{
		{
			name: "negative clock skew",
			prof: x509svid.Profile{ClockSkew: -time.Second},
		},
		{
			name: "clock skew beyond the ceiling",
			prof: x509svid.Profile{ClockSkew: x509svid.MaxClockSkew + time.Second},
		},
		{
			name: "RSA floor below the minimum",
			prof: x509svid.Profile{MinRSABits: 1024},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A bad profile is an operator error. It must surface once, at
			// startup, rather than as a stream of verification failures that
			// look like an attack in progress.
			_, err := x509svid.NewVerifier(set, x509svid.WithProfile(tc.prof))
			assertReason(t, err, x509svid.ReasonBadProfile)
		})
	}
}

// TestProfileZeroValueIsStrictest checks the polarity of every relaxation.
//
// Each knob is named Allow*, so a profile an operator forgot to fill in, or one
// a future refactor fails to populate, fails closed. The test pairs each
// rejection with the single field that turns it into an acceptance, which also
// documents that no knob is a blanket "insecure" switch.
func TestProfileZeroValueIsStrictest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []testsupport.CertOption
		prof x509svid.Profile
		want x509svid.Reason
	}{
		{
			name: "leaf without basicConstraints",
			opts: []testsupport.CertOption{testsupport.WithoutBasicConstraints()},
			prof: x509svid.Profile{AllowLeafWithoutBasicConstraints: true},
			want: x509svid.ReasonMissingBasicConstraints,
		},
		{
			name: "leaf without an mTLS EKU",
			opts: []testsupport.CertOption{testsupport.WithExtKeyUsage()},
			prof: x509svid.Profile{AllowLeafWithoutEKU: true},
			want: x509svid.ReasonMissingEKU,
		},
		{
			name: "leaf without digitalSignature",
			opts: []testsupport.CertOption{testsupport.WithKeyUsage(x509.KeyUsageKeyEncipherment)},
			prof: x509svid.Profile{AllowLeafWithoutDigitalSignature: true},
			want: x509svid.ReasonMissingDigitalSignature,
		},
	}

	ca := testsupport.NewCA(t, tdLocal)
	set := bundle.NewSet(ca.Bundle())
	id := workload(t, tdLocal, "/workload/api")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, _ := ca.IssueSVID(t, id, tc.opts...)

			strict := newVerifier(t, set)
			_, _, err := strict.Verify(chain)
			assertReason(t, err, tc.want)

			relaxed := newVerifier(t, set, x509svid.WithProfile(tc.prof))
			_, _, err = relaxed.Verify(chain)
			assertNoError(t, err, "verifying with the matching relaxation enabled")
		})
	}
}

func TestProfileAllowSigningCertTLSEKU(t *testing.T) {
	t.Parallel()

	root := testsupport.NewCA(t, tdLocal)
	intermediate := root.Intermediate(t, "qredin-test-intermediate",
		testsupport.WithExtKeyUsage(x509.ExtKeyUsageServerAuth))
	chain, _ := intermediate.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	set := bundle.NewSet(root.Bundle())

	strict := newVerifier(t, set)
	_, _, err := strict.Verify(chain)
	assertReason(t, err, x509svid.ReasonSigningCertHasTLSEKU)

	relaxed := newVerifier(t, set,
		x509svid.WithProfile(x509svid.Profile{AllowSigningCertTLSEKU: true}))
	_, _, err = relaxed.Verify(chain)
	assertNoError(t, err, "verifying with AllowSigningCertTLSEKU set")
}

// TestRelaxationsDoNotLeakAcrossRules checks that each knob is narrow.
//
// The failure this guards against is a relaxation implemented as an early
// return that skips the rest of the profile. Here the certificate breaks two
// rules and only one is relaxed, so it must still be rejected — for the other
// reason.
func TestRelaxationsDoNotLeakAcrossRules(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"),
		testsupport.WithExtKeyUsage(),
		testsupport.WithCAFlag())

	v := newVerifier(t, bundle.NewSet(ca.Bundle()),
		x509svid.WithProfile(x509svid.Profile{AllowLeafWithoutEKU: true}))

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonLeafIsCA)
}

// ---------------------------------------------------------------------------
// Inputs and lifecycle
// ---------------------------------------------------------------------------

func TestVerifyRejectsEmptyAndMalformedInput(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	v := newVerifier(t, bundle.NewSet(ca.Bundle()))

	t.Run("empty chain", func(t *testing.T) {
		t.Parallel()
		_, _, err := v.Verify(nil)
		assertReason(t, err, x509svid.ReasonEmptyChain)
	})

	t.Run("no raw certificates", func(t *testing.T) {
		t.Parallel()
		_, _, err := v.VerifyRaw(nil)
		assertReason(t, err, x509svid.ReasonEmptyChain)
	})

	t.Run("raw certificate is not DER", func(t *testing.T) {
		t.Parallel()
		_, _, err := v.VerifyRaw([][]byte{[]byte("not a certificate")})
		assertReason(t, err, x509svid.ReasonChainInvalid)
	})

	t.Run("second raw certificate is not DER", func(t *testing.T) {
		t.Parallel()
		chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"))
		_, _, err := v.VerifyRaw([][]byte{chain[0].Raw, []byte("not a certificate")})
		assertReason(t, err, x509svid.ReasonChainInvalid)
	})
}

// TestVerifyReadsTheBundleSourceOnEveryCall checks that the Verifier is not
// holding a snapshot.
//
// Bundles change underneath a running process: federation is added, a trust
// domain is de-federated, an authority is rotated in. A Verifier that captured
// its roots at construction would keep honouring a revoked federation until the
// process restarted, which is the opposite of what de-federating is for.
func TestVerifyReadsTheBundleSourceOnEveryCall(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	set := bundle.NewSet(local.Bundle())
	v := newVerifier(t, set)

	chain, _ := foreign.IssueSVID(t, workload(t, tdForeign, "/workload/api"))

	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoBundle)

	// Federation is established.
	set.Add(foreign.Bundle())
	_, _, err = v.Verify(chain)
	assertNoError(t, err, "verifying after the peer's bundle was added")

	// Federation is revoked. The next handshake must fail, not the next restart.
	set.Remove(tdForeign)
	_, _, err = v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoBundle)
}

// TestVerifyPropagatesSourceErrors checks the fail-closed direction for a
// source that is unavailable rather than empty.
//
// A datastore timeout must not be indistinguishable from "verified". It is
// reported as ReasonNoBundle: from the verifier's position the two are the same
// statement — we cannot establish that this peer's trust domain is one we
// federate with — and neither is grounds for consulting another bundle.
func TestVerifyPropagatesSourceErrors(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	failing := bundle.SourceFunc(func(spiffeid.TrustDomain) (*bundle.Bundle, error) {
		return nil, errTestSourceUnavailable
	})

	v := newVerifier(t, failing)
	_, _, err := v.Verify(chain)
	assertReason(t, err, x509svid.ReasonNoBundle)
}

func TestVerifierProfileIsReadable(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	want := x509svid.Profile{ClockSkew: time.Minute, AllowLeafWithoutEKU: true}

	v := newVerifier(t, bundle.NewSet(ca.Bundle()), x509svid.WithProfile(want))
	if got := v.Profile(); got != want {
		t.Fatalf("Profile() = %+v, want %+v", got, want)
	}
}

func TestParseChain(t *testing.T) {
	t.Parallel()

	ca := testsupport.NewCA(t, tdLocal)
	chain, _ := ca.IssueSVID(t, workload(t, tdLocal, "/workload/api"))

	got, err := x509svid.ParseChain([][]byte{chain[0].Raw})
	assertNoError(t, err, "ParseChain")
	if len(got) != 1 || !got[0].Equal(chain[0]) {
		t.Fatal("ParseChain did not round-trip the leaf")
	}

	_, err = x509svid.ParseChain(nil)
	assertReason(t, err, x509svid.ReasonEmptyChain)
}
