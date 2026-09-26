package kubernetes_test

import (
	"errors"
	"testing"

	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/authentication/internal/attestation/workload/kubernetes"
)

func TestAttestUsesPodStatusDigest(t *testing.T) {
	selectors, err := kubernetes.Attest(9, fakeResolver{})
	if err != nil {
		t.Fatal(err)
	}
	if !selectors.Contains(attestation.Selector{Type: "k8s.container-image-digest", Value: "sha256:abc"}) {
		t.Fatal("missing immutable image digest")
	}
	if !selectors.Contains(attestation.Selector{Type: "k8s.pod-label:qredin.role", Value: "api"}) {
		t.Fatal("missing pod label")
	}
}

func TestAttestRejectsMissingOrMutableIdentity(t *testing.T) {
	if _, err := kubernetes.Attest(9, nil); !errors.Is(err, kubernetes.ErrPodUnavailable) {
		t.Fatalf("error = %v, want ErrPodUnavailable", err)
	}
	if _, err := kubernetes.Attest(9, tagResolver{}); !errors.Is(err, kubernetes.ErrPodUnavailable) {
		t.Fatalf("tag error = %v, want ErrPodUnavailable", err)
	}
}

func TestAttestAuthenticatedRequiresAuthenticatedNodeView(t *testing.T) {
	if _, err := kubernetes.AttestAuthenticated(9, unauthenticatedResolver{}); !errors.Is(err, kubernetes.ErrPodUnavailable) {
		t.Fatalf("error = %v, want ErrPodUnavailable", err)
	}
}

type fakeResolver struct{}

func (fakeResolver) ResolvePID(int) (kubernetes.Pod, error) {
	return kubernetes.Pod{Namespace: "payments", ServiceAccount: "api", Name: "api-1", UID: "uid-1", NodeName: "node-1", ImageDigest: "sha256:abc", Labels: map[string]string{"qredin.role": "api"}}, nil
}

type tagResolver struct{}

func (tagResolver) ResolvePID(int) (kubernetes.Pod, error) {
	return kubernetes.Pod{Namespace: "payments", ServiceAccount: "api", Name: "api-1", UID: "uid-1", NodeName: "node-1", ImageDigest: "qredin/api:latest"}, nil
}

type unauthenticatedResolver struct{}

func (unauthenticatedResolver) ResolvePID(int) (kubernetes.Pod, error) {
	return fakeResolver{}.ResolvePID(0)
}
func (unauthenticatedResolver) Authenticated() bool { return false }
