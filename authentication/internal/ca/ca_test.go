package ca_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/qredin/qredin/authentication/internal/attestation/node"
	"github.com/qredin/qredin/authentication/internal/ca"
	"github.com/qredin/qredin/authentication/internal/keymanager"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

func TestAuthorityIssuesAndVerifiesSVIDWithoutKeyExport(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	manager := newTestManager(t)
	ctx := context.Background()

	authority, err := ca.NewSelfSigned(ctx, manager, td, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	id, err := spiffeid.FromString("spiffe://prod.identity.example.com/workload/api")
	if err != nil {
		t.Fatalf("building workload ID: %v", err)
	}
	svid, err := authority.IssueSVID(ctx, id, time.Hour)
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}

	verifier, err := x509svid.NewVerifier(bundle.NewSet(bundle.FromX509Authorities(td,
		[]*x509.Certificate{authority.Certificate()})))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	got, _, err := verifier.Verify(svid.Certificates)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != id {
		t.Fatalf("verified ID = %q, want %q", got, id)
	}

	if _, _, err := svid.MarshalRaw(); err == nil {
		t.Fatal("MarshalRaw exported a manager-owned signing key")
	}
}

func TestAuthorityIssuesNodeIdentity(t *testing.T) {
	t.Parallel()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	manager := newTestManager(t)
	authority, err := ca.NewSelfSigned(context.Background(), manager, td, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity := node.NodeIdentity{
		ID:          spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1"),
		TrustDomain: td, Selectors: map[string]string{"instance": "node-1"},
	}
	svid, err := authority.IssueNode(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if svid.ID != identity.ID || !svid.ID.IsWorkload() {
		t.Fatalf("node SVID identity = %q", svid.ID)
	}
}

type testManager struct {
	keys map[string]crypto.Signer
}

func newTestManager(t *testing.T) *testManager {
	t.Helper()
	return &testManager{keys: make(map[string]crypto.Signer)}
}

func (m *testManager) Open(context.Context, keymanager.Environment) error { return nil }

func (m *testManager) Generate(_ context.Context, _ keymanager.KeySpec) (keymanager.Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keymanager.Key{}, err
	}
	id := "test-key-" + string(rune(len(m.keys)+'a'))
	m.keys[id] = nonExportingSigner{Signer: key}
	return keymanager.Key{ID: id, Public: key.Public()}, nil
}

func (m *testManager) Signer(_ context.Context, id string) (crypto.Signer, error) {
	key, ok := m.keys[id]
	if !ok {
		return nil, errors.New("test key not found")
	}
	return key, nil
}

type nonExportingSigner struct{ crypto.Signer }
