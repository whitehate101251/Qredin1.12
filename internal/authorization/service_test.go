package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/qredin/qredin/internal/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockService struct {
	UnimplementedService
	decision *policy.AuthorizationDecision
	err      error
}

func (m *mockService) Check(_ context.Context, _ *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.decision, nil
}

func TestCheckReturnsAllowDecision(t *testing.T) {
	svc := &mockService{
		decision: &policy.AuthorizationDecision{
			RequestID:   "req-1",
			Decision:    policy.DecisionAllow,
			PolicyID:    "pol-1",
			Reason:      "matched allow rule",
			EvaluatedAt: time.Now(),
		},
	}
	provider := NewAuthServiceProvider(svc)
	req := &policy.AuthorizationRequest{
		RequestID:       "req-1",
		SubjectSPIFFEID: "spiffe://example.com/workload",
		Action:          "read",
		Resource:        "database",
		Timestamp:       time.Now(),
	}
	decision, err := provider.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", decision.Decision)
	}
	if decision.PolicyID != "pol-1" {
		t.Fatalf("expected pol-1, got %s", decision.PolicyID)
	}
}

func TestCheckReturnsDenyDecision(t *testing.T) {
	svc := &mockService{
		decision: &policy.AuthorizationDecision{
			RequestID:   "req-2",
			Decision:    policy.DecisionDeny,
			Reason:      "explicit deny rule",
			EvaluatedAt: time.Now(),
		},
	}
	provider := NewAuthServiceProvider(svc)
	req := &policy.AuthorizationRequest{
		RequestID:       "req-2",
		SubjectSPIFFEID: "spiffe://example.com/evil",
		Action:          "delete",
		Resource:        "secrets",
		Timestamp:       time.Now(),
	}
	decision, err := provider.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", decision.Decision)
	}
}

func TestCheckPropagatesError(t *testing.T) {
	svc := &mockService{
		err: status.Error(codes.Internal, "database unavailable"),
	}
	provider := NewAuthServiceProvider(svc)
	req := &policy.AuthorizationRequest{
		RequestID:       "req-3",
		SubjectSPIFFEID: "spiffe://example.com/workload",
		Action:          "read",
		Resource:        "data",
		Timestamp:       time.Now(),
	}
	_, err := provider.Check(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("expected Internal, got %s", st.Code())
	}
}

func TestUnimplementedServiceReturnsUnimplemented(t *testing.T) {
	var svc UnimplementedService
	_, err := svc.Check(context.Background(), &policy.AuthorizationRequest{})
	if err == nil {
		t.Fatal("expected error from unimplemented service")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %s", st.Code())
	}
}

func TestAuthClientInterfaceCompliance(t *testing.T) {
	// Verify NewAuthClient returns an AuthClient
	// We can't test actual gRPC calls without a server, but we can verify
	// the interface is satisfied
	var _ AuthClient = NewAuthClient(nil)
}
