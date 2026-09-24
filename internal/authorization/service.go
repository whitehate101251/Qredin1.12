package authorization

import (
	"context"

	"github.com/qredin/qredin/internal/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthServiceName is the fully-qualified service name.
const AuthServiceName = "qredin.authorization.v1.Authorization"

// AuthCheckMethodName is the method name for Check.
const AuthCheckMethodName = "Check"

// AuthCheck_FullMethodName is the full method name for Check.
const AuthCheck_FullMethodName = "/" + AuthServiceName + "/" + AuthCheckMethodName

// Service is the authorization decision service.
type Service interface {
	Check(ctx context.Context, req *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error)
	mustEmbedUnimplementedService()
}

// UnimplementedService must be embedded for forward compatibility.
type UnimplementedService struct{}

func (UnimplementedService) Check(context.Context, *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error) {
	return nil, status.Error(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedService) mustEmbedUnimplementedService() {}

var _ Service = (*UnimplementedService)(nil)

// AuthServer is the gRPC server interface for the authorization service.
type AuthServer interface {
	Check(ctx context.Context, in *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error)
	mustEmbedUnimplementedAuthServer()
}

// UnimplementedAuthServer must be embedded for forward compatibility.
type UnimplementedAuthServer struct{}

func (UnimplementedAuthServer) Check(context.Context, *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error) {
	return nil, status.Error(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedAuthServer) mustEmbedUnimplementedAuthServer() {}

var _ AuthServer = (*UnimplementedAuthServer)(nil)

// AuthServiceProvider is a gRPC ServiceRegistrar-based authorization service.
type AuthServiceProvider struct {
	UnimplementedService
	svc Service
}

// NewAuthServiceProvider wraps a Service for gRPC registration.
func NewAuthServiceProvider(svc Service) *AuthServiceProvider {
	return &AuthServiceProvider{svc: svc}
}

// Check handles the Check RPC.
func (a *AuthServiceProvider) Check(ctx context.Context, req *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error) {
	return a.svc.Check(ctx, req)
}

func authCheckHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(policy.AuthorizationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	s := srv.(*AuthServiceProvider)
	if interceptor == nil {
		return s.Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthCheck_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return s.Check(ctx, req.(*policy.AuthorizationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RegisterAuthService registers the authorization service with a gRPC server.
func RegisterAuthService(s grpc.ServiceRegistrar, svc Service) {
	s.RegisterService(&AuthServiceDesc, NewAuthServiceProvider(svc))
}

// AuthServiceDesc is the gRPC ServiceDesc for the authorization service.
var AuthServiceDesc = grpc.ServiceDesc{
	ServiceName: AuthServiceName,
	HandlerType: (*AuthServiceProvider)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: AuthCheckMethodName,
			Handler:    authCheckHandler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal/authorization/service.go",
}

// AuthClient is the gRPC client interface for the authorization service.
type AuthClient interface {
	Check(ctx context.Context, in *policy.AuthorizationRequest, opts ...grpc.CallOption) (*policy.AuthorizationDecision, error)
}

// authClient is the gRPC client implementation.
type authClient struct {
	cc grpc.ClientConnInterface
}

// NewAuthClient creates a new authorization service client.
func NewAuthClient(cc grpc.ClientConnInterface) AuthClient {
	return &authClient{cc}
}

// Check calls the Check RPC.
func (c *authClient) Check(ctx context.Context, in *policy.AuthorizationRequest, opts ...grpc.CallOption) (*policy.AuthorizationDecision, error) {
	out := new(policy.AuthorizationDecision)
	err := c.cc.Invoke(ctx, AuthCheck_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}