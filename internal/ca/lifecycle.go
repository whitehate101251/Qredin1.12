package ca

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type AuthorityState string

const (
	AuthorityPrepared AuthorityState = "prepared"
	AuthorityActive   AuthorityState = "active"
	AuthorityOld      AuthorityState = "old"
	AuthorityTainted  AuthorityState = "tainted"
	AuthorityRevoked  AuthorityState = "revoked"
)

var (
	ErrInvalidTransition = errors.New("ca: invalid authority lifecycle transition")
	ErrApprovalRequired  = errors.New("ca: two distinct approvals are required")
	ErrOverlapTooShort   = errors.New("ca: authority overlap is shorter than the maximum SVID TTL")
)

// Lifecycle models the explicit publication/signing lifecycle of an authority.
// It is persistence-friendly: every transition returns the new state and the
// caller can commit it with the same transaction as its audit event.
type Lifecycle struct {
	mu         sync.RWMutex
	state      AuthorityState
	maxSVIDTTL time.Duration
	overlap    time.Duration
}

func NewLifecycle(maxSVIDTTL, overlap time.Duration) (*Lifecycle, error) {
	if maxSVIDTTL <= 0 || overlap < maxSVIDTTL {
		return nil, ErrOverlapTooShort
	}
	return &Lifecycle{state: AuthorityPrepared, maxSVIDTTL: maxSVIDTTL, overlap: overlap}, nil
}

func (l *Lifecycle) State() AuthorityState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state
}

// Activate requires two distinct operator approvals, preventing one operator
// from both preparing and activating a signing authority.
func (l *Lifecycle) Activate(firstApproval, secondApproval string) error {
	if firstApproval == "" || secondApproval == "" || firstApproval == secondApproval {
		return ErrApprovalRequired
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != AuthorityPrepared {
		return fmt.Errorf("%w: %s cannot become active", ErrInvalidTransition, l.state)
	}
	l.state = AuthorityActive
	return nil
}

func (l *Lifecycle) Retire() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != AuthorityActive {
		return fmt.Errorf("%w: %s cannot become old", ErrInvalidTransition, l.state)
	}
	l.state = AuthorityOld
	return nil
}

func (l *Lifecycle) Taint() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != AuthorityActive && l.state != AuthorityOld {
		return fmt.Errorf("%w: %s cannot become tainted", ErrInvalidTransition, l.state)
	}
	l.state = AuthorityTainted
	return nil
}

func (l *Lifecycle) Revoke() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != AuthorityOld && l.state != AuthorityTainted {
		return fmt.Errorf("%w: %s cannot become revoked", ErrInvalidTransition, l.state)
	}
	l.state = AuthorityRevoked
	return nil
}

func (l *Lifecycle) Overlap() time.Duration { return l.overlap }

// LifecycleState is a serializable representation of authority lifecycle state.
type LifecycleState struct {
	State      AuthorityState `json:"state"`
	MaxSVIDTTL time.Duration  `json:"max_svid_ttl"`
	Overlap    time.Duration  `json:"overlap"`
}

// MarshalState returns a serializable representation of the current lifecycle state.
// This is safe to call concurrently and is designed for durable persistence.
func (l *Lifecycle) MarshalState() LifecycleState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return LifecycleState{
		State:      l.state,
		MaxSVIDTTL: l.maxSVIDTTL,
		Overlap:    l.overlap,
	}
}

// UnmarshalState restores lifecycle state from a persisted representation.
// It validates the state before applying it.
func UnmarshalState(ls LifecycleState) (*Lifecycle, error) {
	if ls.MaxSVIDTTL <= 0 || ls.Overlap < ls.MaxSVIDTTL {
		return nil, ErrOverlapTooShort
	}
	switch ls.State {
	case AuthorityPrepared, AuthorityActive, AuthorityOld, AuthorityTainted, AuthorityRevoked:
	default:
		return nil, fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, ls.State)
	}
	return &Lifecycle{
		state:      ls.State,
		maxSVIDTTL: ls.MaxSVIDTTL,
		overlap:    ls.Overlap,
	}, nil
}
