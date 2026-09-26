package ca

import (
	"context"
	"errors"
	"time"

	"github.com/qredin/qredin/authentication/internal/attestation/node"
	"github.com/qredin/qredin/pkg/x509svid"
)

// DefaultNodeSVIDTTL is the default TTL for node identity SVIDs.
const DefaultNodeSVIDTTL = time.Hour

// IssueNode implements the node bootstrap issuance boundary for an authority.
// Node identity is a workload-path SPIFFE ID and uses the same strict SVID path.
func (a *Authority) IssueNode(ctx context.Context, identity node.NodeIdentity) (*x509svid.SVID, error) {
	return a.IssueNodeWithTTL(ctx, identity, DefaultNodeSVIDTTL)
}

// IssueNodeWithTTL issues a node SVID with a configurable TTL.
// The TTL controls how often the node must re-attest to maintain its identity.
func (a *Authority) IssueNodeWithTTL(ctx context.Context, identity node.NodeIdentity, ttl time.Duration) (*x509svid.SVID, error) {
	if err := node.ValidateNodeIdentity(identity); err != nil {
		return nil, err
	}
	if !identity.ID.MemberOf(a.trustDomain) {
		return nil, errors.New("ca: node identity is outside the authority trust domain")
	}
	if ttl <= 0 {
		return nil, errors.New("ca: node SVID TTL must be positive")
	}
	return a.IssueSVID(ctx, identity.ID, ttl)
}
