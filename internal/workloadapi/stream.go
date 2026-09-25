// Package workloadapi contains the transport-neutral lifecycle semantics for
// the SPIFFE Workload API. A later gRPC/UDS adapter must preserve these rules.
package workloadapi

import (
	"context"
	"errors"
	"sync"

	"github.com/qredin/qredin/pkg/bundle"
	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

var (
	ErrPermissionDenied = errors.New("workloadapi: permission denied")
	ErrClosed           = errors.New("workloadapi: stream closed")
	ErrInvalidSnapshot  = errors.New("workloadapi: invalid complete snapshot")
)

// Snapshot is a complete credential state. An omitted SVID or trust domain is
// a redaction, not an instruction to retain the previous value.
type Snapshot struct {
	SVIDs   []*x509svid.SVID
	Bundles *bundle.Set
}

// Validate ensures a snapshot cannot accidentally publish an authority or a
// malformed workload credential.
func (s Snapshot) Validate() error {
	if s.Bundles == nil {
		return ErrInvalidSnapshot
	}
	seen := make(map[spiffeid.ID]struct{}, len(s.SVIDs))
	for _, svid := range s.SVIDs {
		if svid == nil || !svid.ID.IsWorkload() || svid.Leaf() == nil || svid.PrivateKey == nil {
			return ErrInvalidSnapshot
		}
		if _, ok := seen[svid.ID]; ok {
			return ErrInvalidSnapshot
		}
		seen[svid.ID] = struct{}{}
	}
	return nil
}

// Stream delivers complete snapshots. It is safe for one producer and
// multiple lifecycle operations; consumers should use Receive from one
// goroutine, matching a gRPC streaming RPC.
type Stream struct {
	mu       sync.Mutex
	current  Snapshot
	hasState bool
	updates  chan Snapshot
	done     chan struct{}
	closed   bool
	denied   bool
}

// NewStream creates a stream with an initial complete response. Initial state
// is not delivered until Receive is called, so opening a stream cannot lose the
// first credential response.
func NewStream(initial Snapshot) (*Stream, error) {
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	return &Stream{
		current:  initial,
		hasState: true,
		updates:  make(chan Snapshot, 1),
		done:     make(chan struct{}),
	}, nil
}

// Rotate replaces the stream's current credentials with a fresh snapshot.
// This enables SVID rotation without workload restarts. The caller is
// responsible for issuing the new snapshot before the previous SVIDs expire.
func (s *Stream) Rotate(next Snapshot) error {
	return s.Replace(next)
}

// Replace publishes a complete replacement. If an SVID or bundle is absent,
// consumers receive that absence and must remove their cached copy.
func (s *Stream) Replace(next Snapshot) error {
	if err := next.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.hasState && equivalent(s.current, next) {
		return nil
	}
	s.current = next
	s.hasState = true
	// Keep the newest complete state when a slow consumer falls behind. Sending
	// deltas here would make a dropped update retain revoked credentials.
	select {
	case s.updates <- next:
	default:
		select {
		case <-s.updates:
		default:
		}
		s.updates <- next
	}
	return nil
}

// Deny closes the stream and causes pending/future receives to return the
// permission error. A workload that loses registration must stop serving old
// credentials rather than wait for their expiry.
func (s *Stream) Deny() {
	s.closeWith(ErrPermissionDenied)
}

// Close terminates the stream normally.
func (s *Stream) Close() { s.closeWith(ErrClosed) }

// Receive returns the initial complete state, subsequent complete replacements,
// or a terminal lifecycle error.
func (s *Stream) Receive(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	if s.closed {
		err := terminalErrorLocked(s)
		s.mu.Unlock()
		return Snapshot{}, err
	}
	if s.hasState {
		state := s.current
		s.hasState = false
		s.mu.Unlock()
		return state, nil
	}
	done := s.done
	updates := s.updates
	s.mu.Unlock()

	select {
	case state := <-updates:
		return state, nil
	case <-done:
		return Snapshot{}, terminalError(s)
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

func (s *Stream) closeWith(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	// Store the terminal reason in the channel by replacing the state marker;
	// terminalError reads the closed stream's reason from this field.
	if err == ErrPermissionDenied {
		s.denied = true
	}
	for {
		select {
		case <-s.updates:
		default:
			close(s.done)
			return
		}
	}
}

func terminalError(s *Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return terminalErrorLocked(s)
}

func terminalErrorLocked(s *Stream) error {
	if s.denied {
		return ErrPermissionDenied
	}
	return ErrClosed
}

func equivalent(a, b Snapshot) bool {
	if !a.Bundles.Equal(b.Bundles) || len(a.SVIDs) != len(b.SVIDs) {
		return false
	}
	for i := range a.SVIDs {
		left, right := a.SVIDs[i], b.SVIDs[i]
		if left.ID != right.ID || len(left.Certificates) != len(right.Certificates) {
			return false
		}
		for j := range left.Certificates {
			if !left.Certificates[j].Equal(right.Certificates[j]) {
				return false
			}
		}
	}
	return true
}
