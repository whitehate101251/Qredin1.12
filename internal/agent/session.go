// Package agent contains the node-agent identity handoff between attestation,
// registration, and Workload API lifecycle state.
package agent

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/qredin/qredin/internal/attestation"
	unixattestor "github.com/qredin/qredin/internal/attestation/workload/unix"
	"github.com/qredin/qredin/internal/registration"
	"github.com/qredin/qredin/internal/workloadapi"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var ErrSessionDenied = errors.New("agent: workload session denied")

// Resolver is the server-side registration lookup used by the node agent.
type Resolver interface {
	ResolveForAgent(attestation.Selectors, spiffeid.ID) (registration.Entry, error)
}

// Issuer creates the initial complete Workload API state for an approved
// registration. It is where CA/key-manager and durable state are connected.
type Issuer interface {
	Issue(ctx context.Context, entry registration.Entry) (workloadapi.Snapshot, error)
}

// OpenUnixSession performs the security-critical handoff for an accepted UDS
// connection. The workload cannot provide an ID, tenant, trust domain, or
// selector claim to influence this path.
func OpenUnixSession(ctx context.Context, conn *net.UnixConn, parentAgentID spiffeid.ID, resolver Resolver, issuer Issuer) (*workloadapi.Stream, error) {
	if conn == nil || resolver == nil || issuer == nil || !parentAgentID.IsWorkload() {
		return nil, ErrSessionDenied
	}
	evidence, err := unixattestor.AttestUnixConn(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation failed: %v", ErrSessionDenied, err)
	}
	entry, err := resolver.ResolveForAgent(evidence.Selectors, parentAgentID)
	if err != nil {
		return nil, fmt.Errorf("%w: registration lookup failed: %v", ErrSessionDenied, err)
	}
	snapshot, err := issuer.Issue(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("agent: issuing workload credentials: %w", err)
	}
	stream, err := workloadapi.NewStream(snapshot)
	if err != nil {
		return nil, fmt.Errorf("agent: creating workload stream: %w", err)
	}
	return stream, nil
}

// RevokeSession immediately redacts credentials after an attestation or
// registration failure. Closing the stream also clears queued rotations.
func RevokeSession(stream *workloadapi.Stream) {
	if stream != nil {
		stream.Deny()
	}
}
