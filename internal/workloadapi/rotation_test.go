package workloadapi

import (
    "context"
    "crypto"
    "crypto/x509"
    "testing"
    "time"

    "github.com/qredin/qredin/internal/testsupport"
    "github.com/qredin/qredin/pkg/bundle"
    "github.com/qredin/qredin/pkg/spiffeid"
    "github.com/qredin/qredin/pkg/x509svid"
)

func TestRotateDeliversNewSnapshot(t *testing.T) {
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    id := spiffeid.RequireFromString("spiffe://example.com/workload-1")
    ca := testsupport.NewCA(t, td)
    chain1, key1 := ca.IssueSVID(t, id)
    svid1, err := parseTestSVID(chain1, key1)
    if err != nil {
        t.Fatal(err)
    }

    initial := Snapshot{
        SVIDs:   svid1,
        Bundles: bundle.NewSet(ca.Bundle()),
    }
    stream, err := NewStream(initial)
    if err != nil {
        t.Fatal(err)
    }

    // Consume initial state
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()
    _, err = stream.Receive(ctx)
    if err != nil {
        t.Fatal(err)
    }

    // Issue new SVID (rotation)
    chain2, key2 := ca.IssueSVID(t, id)
    svid2, err := parseTestSVID(chain2, key2)
    if err != nil {
        t.Fatal(err)
    }

    rotated := Snapshot{
        SVIDs:   svid2,
        Bundles: bundle.NewSet(ca.Bundle()),
    }

    // Rotate
    if err := stream.Rotate(rotated); err != nil {
        t.Fatal(err)
    }

    // Receive rotated state
    state, err := stream.Receive(ctx)
    if err != nil {
        t.Fatal(err)
    }
    if len(state.SVIDs) != 1 {
        t.Fatalf("expected 1 SVID, got %d", len(state.SVIDs))
    }
    // Verify it's the new SVID (different serial number)
    if state.SVIDs[0].Certificates[0].SerialNumber.Cmp(chain1[0].SerialNumber) == 0 {
        t.Fatal("expected rotated SVID to have different serial")
    }
}

func TestRotateAfterDenyFails(t *testing.T) {
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    id := spiffeid.RequireFromString("spiffe://example.com/workload-1")
    ca := testsupport.NewCA(t, td)
    chain, key := ca.IssueSVID(t, id)
    svid, err := parseTestSVID(chain, key)
    if err != nil {
        t.Fatal(err)
    }

    initial := Snapshot{
        SVIDs:   svid,
        Bundles: bundle.NewSet(ca.Bundle()),
    }
    stream, err := NewStream(initial)
    if err != nil {
        t.Fatal(err)
    }

    stream.Deny()

    // Rotate after deny should fail
    err = stream.Rotate(initial)
    if err != ErrClosed {
        t.Fatalf("expected ErrClosed after deny, got %v", err)
    }
}

// parseTestSVID is a helper to create SVID slice from test CA output
func parseTestSVID(chain []*x509.Certificate, key crypto.Signer) ([]*x509svid.SVID, error) {
    svid, err := x509svid.New(chain, key)
    if err != nil {
        return nil, err
    }
    return []*x509svid.SVID{svid}, nil
}
