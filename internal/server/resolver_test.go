package server

import (
    "context"
    "testing"
    "time"

    "github.com/qredin/qredin/internal/ca"
    "github.com/qredin/qredin/internal/keymanager"
    "github.com/qredin/qredin/internal/workloadapi"
    "github.com/qredin/qredin/pkg/spiffeid"
)

func newTestAuthority(t *testing.T, td spiffeid.TrustDomain) *ca.Authority {
    t.Helper()
    dir := t.TempDir()
    mgr, err := keymanager.NewDiskManager(dir)
    if err != nil {
        t.Fatal(err)
    }
    ctx := context.Background()
    if err := mgr.Open(ctx, keymanager.EnvironmentDevelopment); err != nil {
        t.Fatal(err)
    }
    authority, err := ca.NewSelfSigned(ctx, mgr, td, 24*time.Hour)
    if err != nil {
        t.Fatal(err)
    }
    return authority
}

func TestNewResolverCreation(t *testing.T) {
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    authority := newTestAuthority(t, td)
    r := NewResolver(td, nil, authority) // nil store is OK for construction
    if r == nil {
        t.Fatal("expected non-nil resolver")
    }
}

func TestResolverBundleReturnsTrustDomainBundle(t *testing.T) {
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    authority := newTestAuthority(t, td)
    r := NewResolver(td, nil, authority)

    b, err := r.Bundle(td)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if b.TrustDomain() != td {
        t.Fatalf("expected trust domain %s, got %s", td, b.TrustDomain())
    }
    auths := b.X509Authorities()
    if len(auths) != 1 {
        t.Fatalf("expected 1 authority, got %d", len(auths))
    }
    if !auths[0].Equal(authority.Certificate()) {
        t.Fatal("authority certificate mismatch")
    }
}

func TestResolverBundleRejectsMismatchedDomain(t *testing.T) {
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    otherTD := spiffeid.RequireTrustDomainFromString("spiffe://other.com")
    authority := newTestAuthority(t, td)
    r := NewResolver(td, nil, authority)

    _, err := r.Bundle(otherTD)
    if err == nil {
        t.Fatal("expected error for mismatched trust domain")
    }
}

// Verify compile-time interface conformance
var _ workloadapi.Resolver = (*Resolver)(nil)
