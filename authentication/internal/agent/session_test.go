//go:build linux

package agent_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/qredin/qredin/authentication/internal/agent"
	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/authentication/internal/registration"
	"github.com/qredin/qredin/authentication/internal/workloadapi"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
)

func TestOpenUnixSessionBindsAttestationToRegistration(t *testing.T) {
	t.Parallel()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/workload/api")
	registry := registration.New()
	if err := registry.Put(registration.Entry{
		ID: "registration-1", TenantID: "tenant-1", EnvironmentID: "production", TrustDomain: td,
		WorkloadID: workload, ParentAgentID: parent,
		Selectors: attestation.Selectors{{Type: "unix.uid", Value: ""}},
	}); err == nil {
		t.Fatal("test setup accepted an empty selector")
	}

	// The session test uses a resolver that checks the actual attestor output,
	// while the production registry remains the authority for matching.
	listenerPath := filepath.Join(t.TempDir(), "workload.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: listenerPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientDone := make(chan error, 1)
	go func() {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: listenerPath, Net: "unix"})
		if err == nil {
			defer conn.Close()
		}
		clientDone <- err
	}()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}

	resolver := resolverFunc(func(selectors attestation.Selectors, gotParent spiffeid.ID) (registration.Entry, error) {
		if gotParent != parent || !selectors.ContainsType("unix.binary_sha256") {
			t.Fatal("session did not use kernel-derived attestation")
		}
		return registration.Entry{WorkloadID: workload, ParentAgentID: parent}, nil
	})
	issuer := issuerFunc(func(context.Context, registration.Entry) (workloadapi.Snapshot, error) {
		return workloadapi.Snapshot{Bundles: bundle.NewSet()}, nil
	})
	stream, err := agent.OpenUnixSession(context.Background(), server, parent, resolver, issuer)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := stream.Receive(context.Background())
	if err != nil || snapshot.Bundles == nil {
		t.Fatalf("initial session snapshot = %+v, %v", snapshot, err)
	}
	_ = os.Remove(listenerPath)
}

func TestRevokeSessionRedactsQueuedCredentials(t *testing.T) {
	stream, err := workloadapi.NewStream(workloadapi.Snapshot{Bundles: bundle.NewSet()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	agent.RevokeSession(stream)
	if _, err := stream.Receive(context.Background()); !errors.Is(err, workloadapi.ErrPermissionDenied) {
		t.Fatalf("Receive after revocation = %v", err)
	}
}

type resolverFunc func(attestation.Selectors, spiffeid.ID) (registration.Entry, error)

func (f resolverFunc) ResolveForAgent(s attestation.Selectors, id spiffeid.ID) (registration.Entry, error) {
	return f(s, id)
}

type issuerFunc func(context.Context, registration.Entry) (workloadapi.Snapshot, error)

func (f issuerFunc) Issue(ctx context.Context, e registration.Entry) (workloadapi.Snapshot, error) {
	return f(ctx, e)
}
