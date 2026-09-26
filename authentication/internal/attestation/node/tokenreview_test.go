package node_test

import (
	"context"
	"errors"
	"testing"

	"github.com/qredin/qredin/authentication/internal/attestation/node"
)

func TestValidateProjectedTokenRequiresAuthenticationAndAudience(t *testing.T) {
	username, err := node.ValidateProjectedToken(context.Background(), reviewer{}, "token", "qredin-node")
	if err != nil || username != "system:serviceaccount:qredin:agent" {
		t.Fatalf("result = %q, %v", username, err)
	}
	if _, err := node.ValidateProjectedToken(context.Background(), badReviewer{}, "token", "qredin-node"); !errors.Is(err, node.ErrTokenReviewFailed) {
		t.Fatalf("bad audience error = %v", err)
	}
}

type reviewer struct{}

func (reviewer) Review(context.Context, string, []string) (node.TokenReviewResult, error) {
	return node.TokenReviewResult{Authenticated: true, Username: "system:serviceaccount:qredin:agent", Audiences: []string{"qredin-node"}}, nil
}

type badReviewer struct{}

func (badReviewer) Review(context.Context, string, []string) (node.TokenReviewResult, error) {
	return node.TokenReviewResult{Authenticated: true, Username: "agent", Audiences: []string{"kubernetes"}}, nil
}
