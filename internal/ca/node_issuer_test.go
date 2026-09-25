package ca

import (
	"context"
	"testing"
	"time"

	"github.com/qredin/qredin/internal/attestation/node"
	"github.com/qredin/qredin/internal/keymanager"
	"github.com/qredin/qredin/pkg/spiffeid"
)

func newTestAuthorityForNode(t *testing.T, td spiffeid.TrustDomain) *Authority {
	t.Helper()
	dir := t.TempDir()
	mgr, err := keymanager.NewDiskManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Open(context.Background(), keymanager.EnvironmentDevelopment); err != nil {
		t.Fatal(err)
	}
	auth, err := NewSelfSigned(context.Background(), mgr, td, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestIssueNodeSuccess(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
	auth := newTestAuthorityForNode(t, td)
	id := spiffeid.RequireFromString("spiffe://example.com/node/agent-1")
	identity := node.NodeIdentity{
		ID:          id,
		TrustDomain: td,
		Selectors:   map[string]string{"type": "value"},
	}

	svid, err := auth.IssueNode(context.Background(), identity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svid == nil {
		t.Fatal("expected non-nil SVID")
	}
	if svid.ID != id {
		t.Fatalf("expected ID %s, got %s", id, svid.ID)
	}
}

func TestIssueNodeWithCustomTTL(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
	auth := newTestAuthorityForNode(t, td)
	id := spiffeid.RequireFromString("spiffe://example.com/node/agent-1")
	identity := node.NodeIdentity{
		ID:          id,
		TrustDomain: td,
		Selectors:   map[string]string{"type": "value"},
	}

	customTTL := 30 * time.Minute
	svid, err := auth.IssueNodeWithTTL(context.Background(), identity, customTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svid == nil {
		t.Fatal("expected non-nil SVID")
	}
	// Verify the TTL is approximately correct (within a few minutes for clock skew)
	leaf := svid.Leaf()
	actualTTL := leaf.NotAfter.Sub(leaf.NotBefore)
	// The CA adds 1 minute of clock skew to NotBefore, so actual range is ~31 minutes
	if actualTTL < customTTL || actualTTL > customTTL+2*time.Minute {
		t.Fatalf("expected TTL ~%s, got %s", customTTL, actualTTL)
	}
}

func TestIssueNodeRejectsWrongTrustDomain(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
	otherTD := spiffeid.RequireTrustDomainFromString("spiffe://other.com")
	auth := newTestAuthorityForNode(t, td)
	id := spiffeid.RequireFromString("spiffe://other.com/node/agent-1")
	identity := node.NodeIdentity{
		ID:          id,
		TrustDomain: otherTD,
		Selectors:   map[string]string{"type": "value"},
	}

	_, err := auth.IssueNode(context.Background(), identity)
	if err == nil {
		t.Fatal("expected error for wrong trust domain")
	}
}

func TestIssueNodeRejectsZeroTTL(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
	auth := newTestAuthorityForNode(t, td)
	id := spiffeid.RequireFromString("spiffe://example.com/node/agent-1")
	identity := node.NodeIdentity{
		ID:          id,
		TrustDomain: td,
		Selectors:   map[string]string{"type": "value"},
	}

	_, err := auth.IssueNodeWithTTL(context.Background(), identity, 0)
	if err == nil {
		t.Fatal("expected error for zero TTL")
	}
}

func TestIssueNodeRejectsNegativeTTL(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
	auth := newTestAuthorityForNode(t, td)
	id := spiffeid.RequireFromString("spiffe://example.com/node/agent-1")
	identity := node.NodeIdentity{
		ID:          id,
		TrustDomain: td,
		Selectors:   map[string]string{"type": "value"},
	}

	_, err := auth.IssueNodeWithTTL(context.Background(), identity, -time.Hour)
	if err == nil {
		t.Fatal("expected error for negative TTL")
	}
}
