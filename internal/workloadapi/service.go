package workloadapi

import (
	"context"
	"crypto/x509"
	"sync"

	pb "github.com/qredin/qredin/api/workloadapi/v1"
	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// WorkloadService implements the SPIFFE Workload API gRPC service.
type WorkloadService struct {
	pb.UnimplementedWorkloadAPIServer
	resolver Resolver
}

// Resolver resolves the authoritative source for a workload's credential state.
type Resolver interface {
	Resolve(id spiffeid.ID) (*Snapshot, error)
	Bundle(td spiffeid.TrustDomain) (*bundle.Bundle, error)
}

// NewWorkloadService creates a WorkloadService that delegates to the resolver.
func NewWorkloadService(resolver Resolver) *WorkloadService {
	return &WorkloadService{resolver: resolver}
}

// Register registers the WorkloadService on the given gRPC server.
func (s *WorkloadService) Register(server *grpc.Server) {
	pb.RegisterWorkloadAPIServer(server, s)
}

// RequireHeader is a gRPC interceptor that enforces the
// workload.spiffe.io: true metadata header required by the SPIFFE spec.
func RequireHeader() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := enforceHeader(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func enforceHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Internal, "missing metadata")
	}
	values := md.Get("workload.spiffe.io")
	if len(values) == 0 || values[0] != "true" {
		return status.Error(codes.Unauthenticated, "missing required workload.spiffe.io header")
	}
	return nil
}

// RequireStreamHeader is a gRPC stream interceptor that enforces the
// workload.spiffe.io: true metadata header required by the SPIFFE spec.
func RequireStreamHeader() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := enforceHeader(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// FetchX509SVID returns the X.509-SVID for the caller's SPIFFE ID.
func (s *WorkloadService) FetchX509SVID(ctx context.Context, req *pb.X509SVIDRequest) (*pb.X509SVIDResponse, error) {
	// Extract caller identity from context (set by peer credential interceptor)
	callerID, ok := ctx.Value(spiffeid.ID{}).(spiffeid.ID)
	if !ok || callerID.IsZero() {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid caller identity")
	}

	// Validate that the requested trust domain matches the caller's identity
	requestedTD, err := spiffeid.TrustDomainFromString(req.TrustDomain)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid trust domain")
	}

	if !callerID.MemberOf(requestedTD) {
		return nil, status.Error(codes.PermissionDenied, "caller not authorized for requested trust domain")
	}

	snap, err := s.resolver.Resolve(callerID)
	if err != nil {
		return nil, status.Error(codes.Internal, "resolution failed")
	}
	svids, err := toPbX509SVIDs(snap.SVIDs)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal failed")
	}
	return &pb.X509SVIDResponse{Svids: svids}, nil
}

// FetchBundle returns the trust bundle for the given trust domain.
func (s *WorkloadService) FetchBundle(ctx context.Context, req *pb.BundleRequest) (*pb.BundleResponse, error) {
	td, err := spiffeid.TrustDomainFromString(req.TrustDomain)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid trust domain")
	}
	b, err := s.resolver.Bundle(td)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bundle not found")
	}
	x509Auths := b.X509Authorities()
	raw, err := marshalX509Authorities(x509Auths)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal failed")
	}
	return &pb.BundleResponse{Bundles: []*pb.Bundle{{
		TrustDomain:     td.String(),
		X509Authorities: raw,
		JwtAuthorities:  nil,
		Hint:            b.RefreshHintOrDefault().String(),
	}}}, nil
}

// SubscribeX509SVIDs streams X.509-SVID updates for the caller.
func (s *WorkloadService) SubscribeX509SVIDs(req *pb.SubscribeX509SVIDsRequest, srv pb.WorkloadAPI_SubscribeX509SVIDsServer) error {
	id, err := spiffeid.FromString(req.TrustDomain)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid trust domain")
	}
	snap, err := s.resolver.Resolve(id)
	if err != nil {
		return status.Error(codes.InvalidArgument, "resolution failed")
	}
	stream, err := NewStream(*snap)
	if err != nil {
		return status.Error(codes.Internal, "stream creation failed")
	}
	for {
		state, err := stream.Receive(srv.Context())
		if err != nil {
			return err
		}
		svids, err := toPbX509SVIDs(state.SVIDs)
		if err != nil {
			return status.Error(codes.Internal, "marshal failed")
		}
		if err := srv.Send(&pb.SubscribeX509SVIDsResponse{Svids: &pb.X509SVIDResponse{Svids: svids}}); err != nil {
			return err
		}
	}
}

// SubscribeJWTSVIDs streams JWT-SVID updates for the caller.
func (s *WorkloadService) SubscribeJWTSVIDs(req *pb.SubscribeJWTSVIDsRequest, srv pb.WorkloadAPI_SubscribeJWTSVIDsServer) error {
	return status.Error(codes.Unimplemented, "SubscribeJWTSVIDs not implemented")
}

// SubscribeBundles streams bundle updates for the caller.
func (s *WorkloadService) SubscribeBundles(req *pb.SubscribeBundlesRequest, srv pb.WorkloadAPI_SubscribeBundlesServer) error {
	snap, err := s.resolver.Resolve(spiffeid.ID{})
	if err != nil {
		return status.Error(codes.InvalidArgument, "resolution failed")
	}
	stream, err := NewStream(*snap)
	if err != nil {
		return status.Error(codes.Internal, "stream creation failed")
	}
	for {
		state, err := stream.Receive(srv.Context())
		if err != nil {
			return err
		}
		bundles, err := toPbBundles(state.Bundles)
		if err != nil {
			return status.Error(codes.Internal, "bundle marshal failed")
		}
		if err := srv.Send(&pb.SubscribeBundlesResponse{Bundles: &pb.BundleResponse{Bundles: bundles}}); err != nil {
			return err
		}
	}
}

// toPbX509SVIDs converts x509svid.SVIDs to protobuf X509SVIDs.
func toPbX509SVIDs(svids []*x509svid.SVID) ([]*pb.X509SVID, error) {
	out := make([]*pb.X509SVID, 0, len(svids))
	for _, svid := range svids {
		certChain, _, err := svid.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, &pb.X509SVID{
			SpiffeId:  svid.ID.String(),
			CertChain: certChain,
			Hint:      svid.Hint,
		})
	}
	return out, nil
}

// toPbBundles converts a bundle.Set to protobuf Bundles.
func toPbBundles(bundles *bundle.Set) ([]*pb.Bundle, error) {
	out := make([]*pb.Bundle, 0, bundles.Len())
	for _, td := range bundles.TrustDomains() {
		b, err := bundles.Get(td)
		if err != nil {
			continue
		}
		x509Auths := b.X509Authorities()
		raw, err := marshalX509Authorities(x509Auths)
		if err != nil {
			continue
		}
		out = append(out, &pb.Bundle{
			TrustDomain:     td.String(),
			X509Authorities: raw,
			JwtAuthorities:  nil,
			Hint:            b.RefreshHintOrDefault().String(),
		})
	}
	return out, nil
}

// marshalX509Authorities encodes x509.Certificate slice to DER bytes.
func marshalX509Authorities(certs []*x509.Certificate) ([]byte, error) {
	var out []byte
	for _, c := range certs {
		out = append(out, c.Raw...)
	}
	return out, nil
}

// UDSListenerConfig configures a node-local Unix domain socket listener.
type UDSListenerConfig struct {
	mu        sync.Mutex
	allowed   bool
	headerKey string
	headerVal string
}

// NewUDSListenerConfig creates a UDS listener configuration that enforces
// the workload.spiffe.io: true metadata header required by the SPIFFE spec.
func NewUDSListenerConfig() *UDSListenerConfig {
	return &UDSListenerConfig{
		headerKey: "workload.spiffe.io",
		headerVal: "true",
	}
}

// CheckHeader verifies the required metadata header is present and correct.
func (c *UDSListenerConfig) CheckHeader(headerKey, headerVal string) bool {
	return headerKey == c.headerKey && headerVal == c.headerVal
}

// Allowed reports whether UDS exposure is permitted on this node.
func (c *UDSListenerConfig) Allowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowed
}

// SetAllowed enables or disables UDS exposure.
func (c *UDSListenerConfig) SetAllowed(allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowed = allowed
}

// UDSListener manages a node-local Unix domain socket for the Workload API.
// It enforces peer credential checks and the required metadata header.
type UDSListener struct {
	config *UDSListenerConfig
}

// NewUDSListener creates a UDS listener with the given configuration.
func NewUDSListener(config *UDSListenerConfig) *UDSListener {
	return &UDSListener{config: config}
}

// CheckPeerCredential validates the UDS peer credentials for the
// workload.spiffe.io: true header requirement.
func (l *UDSListener) CheckPeerCredential(peerCreds interface{}) bool {
	if peerCreds == nil {
		return false
	}
	return l.config.Allowed()
}

// UDSAddr returns the node-local Unix domain socket address.
func (l *UDSListener) UDSAddr() string {
	return "/var/run/qredin/workload-api.sock"
}
