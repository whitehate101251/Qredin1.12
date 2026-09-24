package ca

import (
	"context"
	"errors"
	"time"

	"github.com/qredin/qredin/internal/attestation/node"
	"github.com/qredin/qredin/pkg/x509svid"
)

// IssueNode implements the node bootstrap issuance boundary for an authority.
// Node identity is a workload-path SPIFFE ID and uses the same strict SVID path.
func (a *Authority) IssueNode(ctx context.Context, identity node.NodeIdentity) (*x509svid.SVID, error) {
	if err := node.ValidateNodeIdentity(identity); err != nil {
		return nil, err
	}
	if !identity.ID.MemberOf(a.trustDomain) {
		return nil, errors.New("ca: node identity is outside the authority trust domain")
	}
	return a.IssueSVID(ctx, identity.ID, time.Hour)
}
