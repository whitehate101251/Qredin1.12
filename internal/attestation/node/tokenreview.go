package node

import (
	"context"
	"errors"
	"fmt"
)

var ErrTokenReviewFailed = errors.New("node attestation: projected token review failed")

// TokenReviewer is the narrow authenticated Kubernetes TokenReview boundary.
// Implementations must use the node's Kubernetes API client, not workload
// claims or an unauthenticated kubelet endpoint.
type TokenReviewer interface {
	Review(ctx context.Context, token string, audiences []string) (TokenReviewResult, error)
}

type TokenReviewResult struct {
	Authenticated bool
	Username      string
	Audiences     []string
}

// ValidateProjectedToken requires authentication and an exact expected
// audience. A token valid for another Kubernetes API must not bootstrap a
// Qredin node identity.
func ValidateProjectedToken(ctx context.Context, reviewer TokenReviewer, token, expectedAudience string) (string, error) {
	if reviewer == nil || token == "" || expectedAudience == "" {
		return "", ErrTokenReviewFailed
	}
	result, err := reviewer.Review(ctx, token, []string{expectedAudience})
	if err != nil || !result.Authenticated || result.Username == "" {
		return "", ErrTokenReviewFailed
	}
	for _, audience := range result.Audiences {
		if audience == expectedAudience {
			return result.Username, nil
		}
	}
	return "", fmt.Errorf("%w: expected audience was not returned", ErrTokenReviewFailed)
}
