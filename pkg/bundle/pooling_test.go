package bundle_test

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
)

// The package documentation claims that pooled cross-trust-domain validation is
// unrepresentable, not merely discouraged. That claim is only true while the
// Set API stays free of any accessor that returns authorities without being
// told which trust domain they are for.
//
// This test is the guard. It fails when someone adds such a method — for
// example an innocuous-looking Set.AllAuthorities() or Set.CertPool() added to
// make a TLS config easier to build. The fix is never to update the allowlist
// with such a method; it is to make the caller name a trust domain.
func TestSetExposesNoPooledAccessor(t *testing.T) {
	t.Parallel()

	// Every method that may exist on *Set, with a note on why it cannot be used
	// to obtain authorities without naming a trust domain.
	allowed := []struct{ name, why string }{
		{"Get", "takes a trust domain"},
		{"GetBundleForTrustDomain", "takes a trust domain"},
		{"Has", "returns a bool"},
		{"Add", "takes a bundle, which carries its own trust domain"},
		{"Remove", "takes a trust domain"},
		{"TrustDomains", "returns names, not keys"},
		{"Len", "returns an int"},
		{"Clone", "returns a Set, preserving this property"},
		{"Equal", "returns a bool"},
		{"ApplyUpdate", "returns trust domains, not keys"},
	}

	reviewed := make(map[string]string, len(allowed))
	for _, m := range allowed {
		reviewed[m.name] = m.why
	}

	setType := reflect.TypeOf(&bundle.Set{})
	for i := 0; i < setType.NumMethod(); i++ {
		m := setType.Method(i)
		why, ok := reviewed[m.Name]
		if !ok {
			t.Errorf("unreviewed method (*Set).%s: any new Set method must be checked "+
				"against the no-pooling rule in the package documentation before "+
				"being added to the allowlist in this test", m.Name)
			continue
		}
		assertNotPooled(t, fmt.Sprintf("(*Set).%s (%s)", m.Name, why), m.Type)
	}
}

// assertNotPooled fails if a method returns raw key material. Returning
// certificates or a CertPool from a Set-level call is the shape that lets a
// caller verify against the union of every trust domain it knows about.
func assertNotPooled(t *testing.T, name string, fn reflect.Type) {
	t.Helper()

	certSlice := reflect.TypeOf([]*x509.Certificate(nil))
	certPool := reflect.TypeOf(&x509.CertPool{})

	for i := 0; i < fn.NumOut(); i++ {
		switch out := fn.Out(i); out {
		case certSlice, certPool:
			t.Errorf("%s returns %s without naming a trust domain; this is the "+
				"pooled-validation shape the package exists to prevent", name, out)
		}
	}
}

// Bundles are read by validators on request paths while the rotation and
// federation paths write to them. Run with -race; this test is meaningless
// without it.
func TestBundleConcurrentAccess(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	next := testsupport.NewCA(t, tdLocal)

	b := local.Bundle()
	if err := b.AddJWTAuthority("k1", testsupport.NewKey(t).Public()); err != nil {
		t.Fatal(err)
	}

	const iterations = 200
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Alternate the authority set the way a rotation would.
			if i%2 == 0 {
				b.SetX509Authorities([]*x509.Certificate{local.Root(), next.Root()})
			} else {
				b.SetX509Authorities([]*x509.Certificate{local.Root()})
			}
			b.SetSequence(uint64(i))
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = b.X509Authorities()
				_, _ = b.X509Pool()
				_, _ = b.FindJWTAuthority("k1")
				_, _ = b.Sequence()
				_ = b.Clone()
				if _, err := b.Marshal(); err != nil {
					t.Errorf("Marshal: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Whatever interleaving occurred, the bundle must still belong to its trust
	// domain and contain its own root.
	if b.TrustDomain() != tdLocal {
		t.Errorf("trust domain changed to %v", b.TrustDomain())
	}
	if !b.HasX509Authority(local.Root()) {
		t.Error("bundle lost its own authority")
	}
}

func TestSetConcurrentAccess(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)

	set := bundle.NewSet(local.Bundle())

	const iterations = 200
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				set.ApplyUpdate(bundle.NewSet(local.Bundle(), foreign.Bundle()))
			} else {
				set.ApplyUpdate(bundle.NewSet(local.Bundle()))
			}
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// The local bundle is present in every update, so this lookup
				// must never fail regardless of interleaving.
				if _, err := set.Get(tdLocal); err != nil {
					t.Errorf("Get(local): %v", err)
					return
				}
				// The foreign bundle comes and goes; either outcome is fine, but
				// a returned bundle must always be the one that was asked for.
				if b, err := set.Get(tdForeign); err == nil && b.TrustDomain() != tdForeign {
					t.Errorf("Get(%v) returned a bundle for %v", tdForeign, b.TrustDomain())
					return
				}
				_ = set.TrustDomains()
				_ = set.Len()
			}
		}()
	}

	wg.Wait()
}

// A validator must not be able to reach a foreign authority through the local
// trust domain's bundle, even when both are held in the same Set. This is the
// end-to-end statement of the property the rest of this file guards piecemeal.
func TestForeignAuthorityNeverReachableViaLocalBundle(t *testing.T) {
	t.Parallel()

	local := testsupport.NewCA(t, tdLocal)
	foreign := testsupport.NewCA(t, tdForeign)
	set := bundle.NewSet(local.Bundle(), foreign.Bundle())

	localBundle, err := set.Get(tdLocal)
	if err != nil {
		t.Fatal(err)
	}

	// A leaf legitimately issued by the foreign trust domain must not chain
	// against the local bundle's pool.
	foreignID := spiffeid.RequireFromString(tdForeign.IDString() + "/workload/api")
	chain, _ := foreign.IssueSVID(t, foreignID)

	pool, err := localBundle.X509Pool()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("a foreign-issued SVID verified against the local trust domain's bundle")
	}

	// Sanity check in the other direction, so the test above is not passing for
	// an unrelated reason such as a malformed fixture.
	foreignBundle, err := set.Get(tdForeign)
	if err != nil {
		t.Fatal(err)
	}
	foreignPool, err := foreignBundle.X509Pool()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:     foreignPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("the foreign SVID should verify against its own bundle: %v", err)
	}
}
