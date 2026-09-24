// Package node contains node attestation bootstrap primitives.
package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
	"github.com/qredin/qredin/pkg/x509svid"
)

var (
	ErrInvalidJoinToken = errors.New("node attestation: invalid or expired join token")
	ErrRateLimited      = errors.New("node attestation: join rate limit exceeded")
	ErrInvalidNode      = errors.New("node attestation: invalid node identity")
	ErrBootstrapFailed  = errors.New("node attestation: node bootstrap failed")
)

// NodeIssuer is the server-side attestation/issuance boundary used after a
// join token is consumed. Implementations must persist the resulting node
// identity before returning success.
type NodeIssuer interface {
	IssueNode(ctx context.Context, identity NodeIdentity) (*x509svid.SVID, error)
}

// Bootstrap consumes a join token before issuing node identity. A failed
// issuance never restores the token: replayable bootstrap credentials are more
// dangerous than requiring an operator to issue a new one.
func Bootstrap(ctx context.Context, tokens *JoinTokenStore, issuer NodeIssuer, token, source string, identity NodeIdentity) (*x509svid.SVID, error) {
	if tokens == nil || issuer == nil || ValidateNodeIdentity(identity) != nil {
		return nil, ErrBootstrapFailed
	}
	if err := tokens.Consume(token, source); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBootstrapFailed, err)
	}
	svid, err := issuer.IssueNode(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("%w: issuing identity: %v", ErrBootstrapFailed, err)
	}
	return svid, nil
}

const maxJoinTTL = time.Hour

type NodeIdentity struct {
	ID          spiffeid.ID
	TrustDomain spiffeid.TrustDomain
	Selectors   map[string]string
}

func ValidateNodeIdentity(identity NodeIdentity) error {
	if !identity.ID.IsWorkload() || !identity.ID.MemberOf(identity.TrustDomain) {
		return ErrInvalidNode
	}
	if len(identity.Selectors) == 0 {
		return ErrInvalidNode
	}
	return nil
}

type JoinTokenStore struct {
	mu       sync.Mutex
	tokens   map[[32]byte]joinToken
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
	now      func() time.Time
}

type joinToken struct{ expires time.Time }

func NewJoinTokenStore(limit int, window time.Duration) (*JoinTokenStore, error) {
	if limit <= 0 || window <= 0 {
		return nil, errors.New("node attestation: invalid join rate limit")
	}
	return &JoinTokenStore{tokens: make(map[[32]byte]joinToken), attempts: make(map[string][]time.Time), limit: limit, window: window, now: time.Now}, nil
}

// Issue creates a single-use token. Only the hash is retained in memory; the
// returned value is the sole bearer copy and must be delivered out of band.
func (s *JoinTokenStore) Issue(ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > maxJoinTTL {
		return "", fmt.Errorf("node attestation: join TTL must be between 0 and %s", maxJoinTTL)
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("node attestation: generating join token: %w", err)
	}
	hash := sha256.Sum256(bytes)
	s.mu.Lock()
	s.tokens[hash] = joinToken{expires: s.now().Add(ttl)}
	s.mu.Unlock()
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Consume atomically validates, rate-limits, and deletes a token. Replaying a
// previously consumed token is indistinguishable from any invalid token.
func (s *JoinTokenStore) Consume(token, source string) error {
	if token == "" || source == "" {
		return ErrInvalidJoinToken
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowLocked(source, now) {
		return ErrRateLimited
	}
	bytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(bytes) != 32 {
		return ErrInvalidJoinToken
	}
	hash := sha256.Sum256(bytes)
	record, ok := s.tokens[hash]
	if !ok || !now.Before(record.expires) {
		delete(s.tokens, hash)
		return ErrInvalidJoinToken
	}
	delete(s.tokens, hash)
	return nil
}

func (s *JoinTokenStore) allowLocked(source string, now time.Time) bool {
	cutoff := now.Add(-s.window)
	attempts := s.attempts[source][:0]
	for _, attempt := range s.attempts[source] {
		if attempt.After(cutoff) {
			attempts = append(attempts, attempt)
		}
	}
	if len(attempts) >= s.limit {
		s.attempts[source] = attempts
		return false
	}
	s.attempts[source] = append(attempts, now)
	return true
}
