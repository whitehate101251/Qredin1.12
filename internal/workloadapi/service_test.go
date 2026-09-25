package workloadapi

import (
    "context"
    "errors"
    "testing"

    "github.com/qredin/qredin/pkg/bundle"
    "github.com/qredin/qredin/pkg/spiffeid"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
    pb "github.com/qredin/qredin/api/workloadapi/v1"
)

type mockResolver struct {
    snapshot *Snapshot
    bundle   *bundle.Bundle
    err      error
}

func (m *mockResolver) Resolve(_ spiffeid.ID) (*Snapshot, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.snapshot, nil
}

func (m *mockResolver) Bundle(_ spiffeid.TrustDomain) (*bundle.Bundle, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.bundle, nil
}

func TestRequireHeaderRejectsMissingMetadata(t *testing.T) {
    interceptor := RequireHeader()
    ctx := context.Background() // no metadata
    _, err := interceptor(ctx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
        t.Fatal("handler should not be called")
        return nil, nil
    })
    if err == nil {
        t.Fatal("expected error")
    }
    st, ok := status.FromError(err)
    if !ok {
        t.Fatalf("expected gRPC status, got %v", err)
    }
    if st.Code() != codes.Internal {
        t.Fatalf("expected Internal, got %s", st.Code())
    }
}

func TestRequireHeaderRejectsMissingHeader(t *testing.T) {
    interceptor := RequireHeader()
    md := metadata.New(map[string]string{"other": "value"})
    ctx := metadata.NewIncomingContext(context.Background(), md)
    _, err := interceptor(ctx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
        t.Fatal("handler should not be called")
        return nil, nil
    })
    if err == nil {
        t.Fatal("expected error")
    }
    st, _ := status.FromError(err)
    if st.Code() != codes.Unauthenticated {
        t.Fatalf("expected Unauthenticated, got %s", st.Code())
    }
}

func TestRequireHeaderAcceptsValidHeader(t *testing.T) {
    interceptor := RequireHeader()
    md := metadata.New(map[string]string{"workload.spiffe.io": "true"})
    ctx := metadata.NewIncomingContext(context.Background(), md)
    called := false
    _, err := interceptor(ctx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
        called = true
        return "ok", nil
    })
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !called {
        t.Fatal("handler was not called")
    }
}

func TestFetchBundleRejectsInvalidTrustDomain(t *testing.T) {
    svc := NewWorkloadService(&mockResolver{})
    ctx := context.Background()
    // Empty trust domain
    _, err := svc.FetchBundle(ctx, &pb.BundleRequest{TrustDomain: "invalid trust domain"})
    if err == nil {
        t.Fatal("expected error for invalid trust domain")
    }
}

func TestFetchBundleReturnsResolverError(t *testing.T) {
    svc := NewWorkloadService(&mockResolver{err: errors.New("resolver failure")})
    ctx := context.Background()
    // FetchBundle with a resolver that always errors
    td := spiffeid.RequireTrustDomainFromString("spiffe://example.com")
    b := bundle.New(td)
    _ = b // we need to test the resolver error path
    _, err := svc.FetchBundle(ctx, &pb.BundleRequest{TrustDomain: "spiffe://example.com"})
    if err == nil {
        t.Fatal("expected error")
    }
}

func TestUDSListenerConfigDefaults(t *testing.T) {
    cfg := NewUDSListenerConfig()
    if cfg.Allowed() {
        t.Fatal("expected not allowed by default")
    }
    cfg.SetAllowed(true)
    if !cfg.Allowed() {
        t.Fatal("expected allowed after SetAllowed(true)")
    }
    cfg.SetAllowed(false)
    if cfg.Allowed() {
        t.Fatal("expected not allowed after SetAllowed(false)")
    }
}

func TestUDSListenerConfigCheckHeader(t *testing.T) {
    cfg := NewUDSListenerConfig()
    if !cfg.CheckHeader("workload.spiffe.io", "true") {
        t.Fatal("expected valid header to pass")
    }
    if cfg.CheckHeader("workload.spiffe.io", "false") {
        t.Fatal("expected invalid value to fail")
    }
    if cfg.CheckHeader("other.header", "true") {
        t.Fatal("expected wrong key to fail")
    }
}

func TestUDSListenerCheckPeerCredential(t *testing.T) {
    cfg := NewUDSListenerConfig()
    listener := NewUDSListener(cfg)

    // Not allowed by default
    if listener.CheckPeerCredential("some-cred") {
        t.Fatal("expected peer check to fail when not allowed")
    }

    // Nil creds always fail
    if listener.CheckPeerCredential(nil) {
        t.Fatal("expected nil creds to fail")
    }

    cfg.SetAllowed(true)
    if !listener.CheckPeerCredential("some-cred") {
        t.Fatal("expected peer check to pass when allowed")
    }
}

func TestUDSListenerAddr(t *testing.T) {
    cfg := NewUDSListenerConfig()
    listener := NewUDSListener(cfg)
    addr := listener.UDSAddr()
    if addr != "/var/run/qredin/workload-api.sock" {
        t.Fatalf("unexpected addr: %s", addr)
    }
}
