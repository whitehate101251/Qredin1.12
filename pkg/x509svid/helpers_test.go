package x509svid_test

import (
	"errors"
	"testing"

	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

// errTestSourceUnavailable stands in for a bundle source that is broken rather
// than empty: a datastore timeout, a cache that has not warmed, a federation
// endpoint that is down.
//
// Deliberately not bundle.ErrBundleNotFound. The distinction under test is that
// "this trust domain is not one we federate with" and "we cannot currently tell"
// arrive by different paths and must both fail closed.
var errTestSourceUnavailable = errors.New("bundle source unavailable")

// The trust domains used across this package's tests.
//
// Three, not two: a verifier that consults a single bundle looks correct with
// two, because the only bundle present is also the right one. tdUnknown exists
// so that "we have no bundle for this peer" and "the chain did not build" can
// be told apart, and tdForeign so that the set genuinely contains a bundle the
// verifier must decline to use.
var (
	tdLocal   = spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	tdForeign = spiffeid.RequireTrustDomainFromString("partner.identity.example.net")
	tdUnknown = spiffeid.RequireTrustDomainFromString("stranger.example.org")
)

// workload returns a workload ID in td.
func workload(t *testing.T, td spiffeid.TrustDomain, path string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromPath(td, path)
	if err != nil {
		t.Fatalf("building workload ID %q in %q: %v", path, td, err)
	}
	return id
}

// newVerifier builds a Verifier or fails the test.
func newVerifier(t *testing.T, source bundle.Source, opts ...x509svid.Option) *x509svid.Verifier {
	t.Helper()
	v, err := x509svid.NewVerifier(source, opts...)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// assertReason fails unless err is a verification failure carrying want.
//
// Tests assert on the Reason rather than on message text. A test that matches
// on a substring passes when the code fails for an unrelated cause that happens
// to share a word, which in a security test means the property under test was
// never exercised.
func assertReason(t *testing.T, err error, want x509svid.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected failure with reason %q, got success", want)
	}
	got, ok := x509svid.ReasonOf(err)
	if !ok {
		t.Fatalf("error does not carry a Reason: %v", err)
	}
	if got != want {
		t.Fatalf("reason = %q, want %q (error: %v)", got, want, err)
	}
}

// assertNoError fails on any error.
func assertNoError(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}
