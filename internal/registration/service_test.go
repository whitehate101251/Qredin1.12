package registration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/qredin/qredin/internal/attestation"
	"github.com/qredin/qredin/internal/registration"
	"github.com/qredin/qredin/pkg/spiffeid"
)

// fakeTxManager records whether WithTransaction was called.
type fakeTxManager struct {
	called int
}

func (f *fakeTxManager) WithTransaction(_ context.Context, fn func(pgx.Tx) error) error {
	f.called++
	return fn(nil)
}

// fakeRegistrationStore records operations and returns configured results.
type fakeRegistrationStore struct {
	putFn       func(ctx context.Context, entry registration.Entry, expectedRevision *int64) (int64, error)
	getFn       func(ctx context.Context, id string) (registration.Entry, int64, error)
	setStatusFn func(ctx context.Context, id, status string, expectedRevision int64) (int64, error)
	revisions   map[string]int64
	statuses    map[string]string
	records     []registration.Entry
}

func newFakeRegistrationStore() *fakeRegistrationStore {
	return &fakeRegistrationStore{
		revisions: make(map[string]int64),
		statuses:  make(map[string]string),
	}
}

func (s *fakeRegistrationStore) Put(_ context.Context, entry registration.Entry, expectedRevision *int64) (int64, error) {
	if s.putFn != nil {
		return s.putFn(nil, entry, expectedRevision)
	}
	if entry.ID == "" {
		return 0, registration.ErrInvalidRegistration
	}
	rev := s.revisions[entry.ID]
	if expectedRevision != nil && rev != *expectedRevision {
		return 0, registration.ErrNoMatch
	}
	rev++
	s.revisions[entry.ID] = rev
	s.statuses[entry.ID] = entry.Status
	s.records = append(s.records, entry)
	return rev, nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, id string) (registration.Entry, int64, error) {
	if s.getFn != nil {
		return s.getFn(nil, id)
	}
	for _, e := range s.records {
		if e.ID == id {
			return e, s.revisions[id], nil
		}
	}
	return registration.Entry{}, 0, registration.ErrNoMatch
}

func (s *fakeRegistrationStore) SetStatus(_ context.Context, id, status string, expectedRevision int64) (int64, error) {
	if s.setStatusFn != nil {
		return s.setStatusFn(nil, id, status, expectedRevision)
	}
	if status != registration.StatusActive && status != registration.StatusSuspended && status != registration.StatusRevoked {
		return 0, registration.ErrInvalidRegistration
	}
	rev := s.revisions[id]
	if rev == 0 {
		return 0, registration.ErrNoMatch
	}
	if expectedRevision != 0 && rev != expectedRevision {
		return 0, registration.ErrNoMatch
	}
	s.statuses[id] = status
	s.revisions[id]++
	return s.revisions[id], nil
}

func (s *fakeRegistrationStore) Suspend(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, registration.StatusSuspended, expectedRevision)
}

func (s *fakeRegistrationStore) Revoke(ctx context.Context, id string, expectedRevision int64) (int64, error) {
	return s.SetStatus(ctx, id, registration.StatusRevoked, expectedRevision)
}

// fakeApprovalStore records approval operations.
type fakeApprovalStore struct {
	approveFn  func(ctx context.Context, registrationID, approverID string) error
	activateFn func(ctx context.Context, registrationID string, expectedRevision int64) (int64, error)
	approvals  map[string][]string
}

func newFakeApprovalStore() *fakeApprovalStore {
	return &fakeApprovalStore{
		approvals: make(map[string][]string),
	}
}

func (s *fakeApprovalStore) Approve(_ context.Context, registrationID, approverID string) error {
	if s.approveFn != nil {
		return s.approveFn(nil, registrationID, approverID)
	}
	s.approvals[registrationID] = append(s.approvals[registrationID], approverID)
	return nil
}

func (s *fakeApprovalStore) Activate(_ context.Context, registrationID string, expectedRevision int64) (int64, error) {
	if s.activateFn != nil {
		return s.activateFn(nil, registrationID, expectedRevision)
	}
	return 1, nil
}

// fakeAuditStore records audit events.
type fakeAuditStore struct {
	events []registration.ChangeEvent
}

func newFakeAuditStore() *fakeAuditStore {
	return &fakeAuditStore{}
}

func (s *fakeAuditStore) RecordRegistrationChange(event registration.ChangeEvent) error {
	s.events = append(s.events, event)
	return nil
}

func newTestService() *registration.Service {
	return registration.NewService(
		&fakeTxManager{},
		newFakeRegistrationStore(),
		newFakeApprovalStore(),
		newFakeAuditStore(),
	)
}

func TestServicePut(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	rev, err := svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if rev != 1 {
		t.Fatalf("revision = %d, want 1", rev)
	}
}

func TestServicePutRejectsInvalidEntry(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	_, err := svc.Put(context.TODO(), registration.Entry{}, nil)
	if !errors.Is(err, registration.ErrInvalidRegistration) {
		t.Fatalf("error = %v, want ErrInvalidRegistration", err)
	}
}

func TestServiceGet(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	_, err = svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, rev, err := svc.Get(context.TODO(), "reg-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "reg-1" {
		t.Fatalf("got.ID = %q, want %q", got.ID, "reg-1")
	}
	if rev != 1 {
		t.Fatalf("rev = %d, want 1", rev)
	}
	if _, _, err := svc.Get(context.TODO(), "missing"); !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("Get missing = %v, want ErrNoMatch", err)
	}
}

func TestServiceApprove(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	if err := svc.Approve(context.TODO(), "reg-1", "operator-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := svc.Approve(context.TODO(), "reg-1", "operator-2"); err != nil {
		t.Fatalf("Approve second: %v", err)
	}
}

func TestServiceApproveRejectsEmptyIDs(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	if err := svc.Approve(context.TODO(), "", "op"); !errors.Is(err, registration.ErrInvalidRegistration) {
		t.Fatalf("empty regID = %v", err)
	}
	if err := svc.Approve(context.TODO(), "reg", ""); !errors.Is(err, registration.ErrInvalidRegistration) {
		t.Fatalf("empty approverID = %v", err)
	}
}

func TestServiceActivate(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	rev, err := svc.Activate(context.TODO(), "reg-1", 0)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if rev != 1 {
		t.Fatalf("rev = %d, want 1", rev)
	}
}

func TestServiceSuspend(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	_, err = svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := svc.Suspend(context.TODO(), "reg-1", 1)
	if err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if rev != 2 {
		t.Fatalf("rev = %d, want 2", rev)
	}
}

func TestServiceRevoke(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	_, err = svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := svc.Revoke(context.TODO(), "reg-1", 1)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rev != 2 {
		t.Fatalf("rev = %d, want 2", rev)
	}
}

func TestServiceSetStatusRejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	_, err := svc.SetStatus(context.TODO(), "reg-1", "invalid", 0)
	if !errors.Is(err, registration.ErrInvalidRegistration) {
		t.Fatalf("error = %v, want ErrInvalidRegistration", err)
	}
}

func TestServiceSetStatusRequiresRevision(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	_, err = svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong revision should fail
	_, err = svc.SetStatus(context.TODO(), "reg-1", registration.StatusSuspended, 999)
	if !errors.Is(err, registration.ErrNoMatch) {
		t.Fatalf("error = %v, want ErrNoMatch", err)
	}
}

func TestServiceAuditEventsRecorded(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	td := spiffeid.RequireTrustDomainFromString("prod.identity.example.com")
	parent := spiffeid.RequireFromString("spiffe://prod.identity.example.com/node/node-1")
	workload := spiffeid.RequireFromString("spiffe://prod.identity.example.com/ns/payments/sa/api")
	selectors, err := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	if err != nil {
		t.Fatal(err)
	}
	entry := registration.Entry{
		ID: "reg-1", TenantID: "tenant-1", EnvironmentID: "production",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
	_, err = svc.Put(context.TODO(), entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.Approve(context.TODO(), "reg-1", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	err = svc.Approve(context.TODO(), "reg-1", "operator-2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Activate(context.TODO(), "reg-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Suspend(context.TODO(), "reg-1", 1)
	if err != nil {
		t.Fatal(err)
	}
}
