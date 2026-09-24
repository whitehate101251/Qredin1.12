package workloadapi_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/qredin/qredin/internal/testsupport"
	"github.com/qredin/qredin/internal/workloadapi"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

func TestStreamDeliversCompleteReplacementAndRedacts(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	ca := testsupport.NewCA(t, td)
	id := spiffeid.RequireFromString("spiffe://prod.identity.example.com/workload/api")
	chain, key := ca.IssueSVID(t, id)
	certDER, keyDER := rawMaterial(t, chain, key)
	first, err := x509svid.ParseRaw(certDER, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	initial := workloadapi.Snapshot{SVIDs: []*x509svid.SVID{first}, Bundles: bundle.NewSet(ca.Bundle())}
	stream, err := workloadapi.NewStream(initial)
	if err != nil {
		t.Fatal(err)
	}

	got, err := stream.Receive(context.Background())
	if err != nil || len(got.SVIDs) != 1 || got.Bundles.Len() != 1 {
		t.Fatalf("initial Receive = %+v, %v", got, err)
	}

	// The replacement is complete: both the SVID and bundle are absent, so a
	// consumer must clear both cached credentials and trust relationships.
	if err := stream.Replace(workloadapi.Snapshot{Bundles: bundle.NewSet()}); err != nil {
		t.Fatal(err)
	}
	redacted, err := stream.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(redacted.SVIDs) != 0 || redacted.Bundles.Len() != 0 {
		t.Fatalf("redaction snapshot retained state: %+v", redacted)
	}
}

func TestStreamCoalescesRotationsAndDeniesAfterRevocation(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	ca := testsupport.NewCA(t, td)
	stream, err := workloadapi.NewStream(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := stream.Replace(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())}); err != nil {
			t.Fatal(err)
		}
	}
	stream.Deny()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := stream.Receive(ctx); !errors.Is(err, workloadapi.ErrPermissionDenied) {
		t.Fatalf("Receive after Deny = %v, want permission denied", err)
	}
}

func TestStreamCancellationReturnsContextError(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	ca := testsupport.NewCA(t, td)
	stream, err := workloadapi.NewStream(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stream.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive after cancel = %v, want context canceled", err)
	}
}

func TestStreamCloseReturnsClosedError(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	ca := testsupport.NewCA(t, td)
	stream, err := workloadapi.NewStream(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())})
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if _, err := stream.Receive(context.Background()); !errors.Is(err, workloadapi.ErrClosed) {
		t.Fatalf("Receive after Close = %v, want closed", err)
	}
}

func TestStreamReplaceAfterCloseReturnsClosedError(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	ca := testsupport.NewCA(t, td)
	stream, err := workloadapi.NewStream(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())})
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if err := stream.Replace(workloadapi.Snapshot{Bundles: bundle.NewSet(ca.Bundle())}); !errors.Is(err, workloadapi.ErrClosed) {
		t.Fatalf("Replace after Close = %v, want closed", err)
	}
}

func rawMaterial(t *testing.T, chain []*x509.Certificate, key crypto.Signer) ([]byte, []byte) {
	t.Helper()
	var certDER []byte
	for _, cert := range chain {
		certDER = append(certDER, cert.Raw...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyDER
}
