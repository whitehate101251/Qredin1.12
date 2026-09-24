package registration_test

import (
	"errors"
	"testing"

	"github.com/qredin/qredin/internal/attestation"
	"github.com/qredin/qredin/internal/registration"
	"github.com/qredin/qredin/pkg/spiffeid"
)

func TestResolveUsesAttestedSelectorsOnly(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	selectors, err := attestation.NewSelectors(
		attestation.Selector{Type: "k8s.ns", Value: "payments"},
		attestation.Selector{Type: "k8s.sa", Value: "api"},
		attestation.Selector{Type: "k8s.container-image-digest", Value: "sha256:abc"},
	)
	if err != nil {
		t.Fatal(err)
	}

	registry := registration.New()
	if err := registry.Put(registration.Entry{
		ID: "registration-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent, Selectors: selectors,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := registry.Resolve(selectors)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.WorkloadID != workload {
		t.Fatalf("resolved workload = %q, want %q", got.WorkloadID, workload)
	}

	// A caller-declared identity is not an input to Resolve. Different claims
	// cannot change the server-side registration that the attestation selects.
	claimed := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/admin/sa/root")
	if claimed == got.WorkloadID {
		t.Fatal("test setup did not create a distinct claimed identity")
	}
}

func TestResolveFailsClosedForMissingOrAmbiguousSelectors(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	base, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	registry := registration.New()
	entry := func(id, path string) registration.Entry {
		return registration.Entry{
			ID: id, TenantID: "tenant-1", EnvironmentID: "production", TrustDomain: td,
			WorkloadID:    spiffeid.RequireFromString("spiffe://prod.identity.example.com" + path),
			ParentAgentID: parent, Selectors: base,
		}
	}
	if err := registry.Put(entry("one", "/workload/one")); err != nil {
		t.Fatal(err)
	}

	missing, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "2000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(missing); !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("missing selector error = %v, want ErrNoMatch", err)
	}

	if err := registry.Put(entry("two", "/workload/two")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(base); !errors.Is(err, registration.ErrAmbiguous) {
		t.Fatalf("ambiguous selector error = %v, want ErrAmbiguous", err)
	}
}

func TestPutRejectsCrossTrustDomainWorkload(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	foreign := spiffeid.RequireFromString("spiffe://other.example.com/workload/api")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	err = registration.New().Put(registration.Entry{
		ID: "bad", TenantID: "tenant-1", EnvironmentID: "production", TrustDomain: td,
		WorkloadID: foreign, ParentAgentID: parent, Selectors: selectors,
	})
	if !errors.Is(err, registration.ErrInvalidRegistration) {
		t.Fatalf("error = %v, want ErrInvalidRegistration", err)
	}
}

func TestResolveForAgentBindsRegistrationToParentAgent(t *testing.T) {
	t.Parallel()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	otherParent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-2")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/workload/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	registry := registration.New()
	if err := registry.Put(registration.Entry{
		ID: "agent-bound", TenantID: "tenant-1", EnvironmentID: "production", TrustDomain: td,
		WorkloadID: workload, ParentAgentID: parent, Selectors: selectors,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveForAgent(selectors, otherParent); !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("wrong parent error = %v, want ErrNoMatch", err)
	}
	if _, err := registry.ResolveForAgent(selectors, parent); err != nil {
		t.Fatalf("matching parent: %v", err)
	}
}

func TestRegistrationLifecycleStopsIssuance(t *testing.T) {
	t.Parallel()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/workload/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	registry := registration.New()
	if err := registry.Put(registration.Entry{ID: "one", TenantID: "tenant", EnvironmentID: "prod", TrustDomain: td, WorkloadID: workload, ParentAgentID: parent, Selectors: selectors}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Suspend("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveForAgent(selectors, parent); !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("suspended resolve = %v", err)
	}
	if err := registry.Activate("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveForAgent(selectors, parent); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveForAgent(selectors, parent); !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("revoked resolve = %v", err)
	}
}

func TestRegistrationChangesAreAudited(t *testing.T) {
	t.Parallel()
	sink := &auditSink{}
	registry := registration.New()
	registry.SetAuditSink(sink)
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/one")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/workload/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(registration.Entry{ID: "one", TenantID: "t", EnvironmentID: "p", TrustDomain: td, ParentAgentID: parent, WorkloadID: workload, Selectors: selectors}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Suspend("one"); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 || sink.events[1].Status != registration.StatusSuspended {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

type auditSink struct{ events []registration.ChangeEvent }

func (s *auditSink) RecordRegistrationChange(event registration.ChangeEvent) error {
	s.events = append(s.events, event)
	return nil
}
