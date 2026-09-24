package node_test

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

	"github.com/qredin/qredin/internal/attestation/node"
	"github.com/qredin/qredin/internal/ca"
	"github.com/qredin/qredin/internal/keymanager"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

func TestJoinTokenIsSingleUseAndRateLimited(t *testing.T) {
	store, err := node.NewJoinTokenStore(3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(token, "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(token, "node-a"); !errors.Is(err, node.ErrInvalidJoinToken) {
		t.Fatalf("replay error = %v", err)
	}
	if err := store.Consume("bad", "node-a"); !errors.Is(err, node.ErrInvalidJoinToken) {
		t.Fatalf("invalid error = %v", err)
	}
	if err := store.Consume("bad", "node-a"); !errors.Is(err, node.ErrRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestNodeIdentityMustBeWorkloadInItsTrustDomain(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	valid := node.NodeIdentity{ID: spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/one"), TrustDomain: td, Selectors: map[string]string{"instance": "one"}}
	if err := node.ValidateNodeIdentity(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.ID = spiffeid.RequireFromString("spiffe://other.example.com/node/one")
	if !errors.Is(node.ValidateNodeIdentity(invalid), node.ErrInvalidNode) {
		t.Fatal("accepted cross-domain node identity")
	}
}

func TestBootstrapConsumesTokenBeforeIssuingIdentity(t *testing.T) {
	store, err := node.NewJoinTokenStore(5, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	identity := node.NodeIdentity{ID: spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/one"), TrustDomain: td, Selectors: map[string]string{"instance": "one"}}
	issuer := issuerFunc(func(context.Context, node.NodeIdentity) (*x509svid.SVID, error) { return nil, nil })
	if _, err := node.Bootstrap(context.Background(), store, issuer, token, "node-a", identity); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Bootstrap(context.Background(), store, issuer, token, "node-a", identity); !errors.Is(err, node.ErrBootstrapFailed) {
		t.Fatalf("replay bootstrap = %v", err)
	}
}

func TestBootstrapIssuesVerifiableNodeSVID(t *testing.T) {
	t.Parallel()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	manager := newTestManager(t)
	authority, err := ca.NewSelfSigned(context.Background(), manager, td, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store, err := node.NewJoinTokenStore(5, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity := node.NodeIdentity{ID: spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/one"), TrustDomain: td, Selectors: map[string]string{"instance": "one"}}
	svid, err := node.Bootstrap(context.Background(), store, authority, token, "node-a", identity)
	if err != nil {
		t.Fatal(err)
	}
	if svid.ID != identity.ID {
		t.Fatalf("issued SVID ID = %q, want %q", svid.ID, identity.ID)
	}
	verifier, err := x509svid.NewVerifier(bundle.NewSet(bundle.FromX509Authorities(td,
		[]*x509.Certificate{authority.Certificate()})))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.Verify(svid.Certificates); err != nil {
		t.Fatalf("verification failed: %v", err)
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

type issuerFunc func(context.Context, node.NodeIdentity) (*x509svid.SVID, error)

func (f issuerFunc) IssueNode(ctx context.Context, identity node.NodeIdentity) (*x509svid.SVID, error) {
	return f(ctx, identity)
}
