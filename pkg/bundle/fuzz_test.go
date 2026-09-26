package bundle_test

import (
	"encoding/base64"
	"testing"

	"github.com/qredin/qredin/pkg/testsupport"
	"github.com/qredin/qredin/pkg/bundle"
)

// Bundle documents arrive from federated peers over the network. Parse is
// therefore an untrusted-input parser, and the fuzz target asserts the
// properties the rest of the system relies on rather than merely checking that
// it does not crash.
//
//  1. Parsing never panics. A panic in the federation refresher takes down the
//     process that issues identities.
//  2. A parsed bundle belongs to the trust domain the caller named. A document
//     can never reassign itself.
//  3. Anything we can ingest, we can re-publish. Qredin mirrors foreign
//     bundles, so a document that parses but fails to marshal would strand the
//     mirror in a state it cannot serve.
//  4. Parsing is idempotent: re-parsing our own output yields an equal bundle.
//     Without this, a bundle could change meaning simply by passing through us.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"spiffe_sequence":1,"spiffe_refresh_hint":300,"keys":[]}`))
	f.Add([]byte(`{"spiffe_refresh_hint":-1,"keys":[]}`))
	f.Add([]byte(`{"keys":[{"use":"x509-svid"}]}`))
	f.Add([]byte(`{"keys":[{"use":"jwt-svid","kid":"a","kty":"EC","crv":"P-256"}]}`))
	f.Add([]byte(`{"keys":[{"use":"unrecognised","kty":"EC"}]}`))
	f.Add([]byte(`{"keys":null}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	// A real, well-formed document, so the fuzzer has a valid starting point to
	// mutate rather than having to discover DER from scratch.
	ca := testsupport.NewCA(f, tdLocal)
	seed := bundle.New(tdLocal)
	seed.AddX509Authority(ca.Root())
	if err := seed.AddJWTAuthority("seed", testsupport.NewKey(f).Public()); err != nil {
		f.Fatal(err)
	}
	seed.SetSequence(7)
	seed.SetRefreshHint(bundle.DefaultRefreshHint)
	doc, err := seed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(doc)

	// The same document with the certificate re-encoded, to give the mutator an
	// easy handle on the DER bytes.
	f.Add([]byte(`{"keys":[{"use":"x509-svid","x5c":["` +
		base64.StdEncoding.EncodeToString(ca.Root().Raw) + `"]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := bundle.Parse(tdLocal, data)
		if err != nil {
			if b != nil {
				t.Fatal("Parse returned both a bundle and an error")
			}
			return
		}

		if b.TrustDomain() != tdLocal {
			t.Fatalf("parsed bundle claims trust domain %v, want %v", b.TrustDomain(), tdLocal)
		}

		out, err := b.Marshal()
		if err != nil {
			t.Fatalf("a bundle that parsed must also marshal: %v", err)
		}

		again, err := bundle.Parse(tdLocal, out)
		if err != nil {
			t.Fatalf("re-parsing our own output failed: %v", err)
		}
		if !again.Equal(b) {
			t.Fatal("parse is not idempotent: re-parsed bundle differs from the original")
		}

		// Marshalling twice must be byte-identical, or a bundle digest cannot be
		// used to detect real changes.
		out2, err := again.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(out2) {
			t.Fatal("marshal is not deterministic")
		}
	})
}
