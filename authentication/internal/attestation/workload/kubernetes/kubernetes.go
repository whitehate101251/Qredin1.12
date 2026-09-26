// Package kubernetes implements Kubernetes workload selector attestation.
package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/qredin/qredin/authentication/internal/attestation"
)

var ErrPodUnavailable = errors.New("kubernetes attestation: pod metadata unavailable")

// Pod is the verified kubelet/API-server view of a workload. ImageDigest is
// sourced from status, never from the mutable pod spec image tag.
type Pod struct {
	Namespace      string
	ServiceAccount string
	Name           string
	UID            string
	NodeName       string
	ImageDigest    string
	Labels         map[string]string
}

type Resolver interface {
	ResolvePID(pid int) (Pod, error)
}

// AuthenticatedResolver marks a resolver backed by an authenticated kubelet or
// API-server client. Plain metadata resolvers are insufficient for issuance.
type AuthenticatedResolver interface {
	Resolver
	Authenticated() bool
}

type PIDPodMapper interface {
	PodForPID(pid int) (namespace, name string, err error)
}

// HTTPResolver reads pod state from an authenticated Kubernetes API endpoint.
// The caller must provide a client configured with pinned CA trust and a
// short-lived service-account credential; plain HTTP and empty bearer tokens
// are rejected at construction.
type HTTPResolver struct {
	endpoint string
	token    string
	mapper   PIDPodMapper
	client   *http.Client
}

func NewHTTPResolver(endpoint, token string, mapper PIDPodMapper, client *http.Client) (*HTTPResolver, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || token == "" || mapper == nil || client == nil {
		return nil, ErrPodUnavailable
	}
	return &HTTPResolver{endpoint: strings.TrimRight(endpoint, "/"), token: token, mapper: mapper, client: client}, nil
}

func (r *HTTPResolver) Authenticated() bool { return r != nil && r.token != "" }

func (r *HTTPResolver) ResolvePID(pid int) (Pod, error) {
	namespace, name, err := r.mapper.PodForPID(pid)
	if err != nil || namespace == "" || name == "" {
		return Pod{}, ErrPodUnavailable
	}
	request, err := http.NewRequest(http.MethodGet, r.endpoint+"/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods/"+url.PathEscape(name), nil)
	if err != nil {
		return Pod{}, ErrPodUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+r.token)
	response, err := r.client.Do(request)
	if err != nil {
		return Pod{}, ErrPodUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Pod{}, ErrPodUnavailable
	}
	var document podDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return Pod{}, ErrPodUnavailable
	}
	imageDigest := ""
	for _, status := range document.Status.ContainerStatuses {
		if strings.HasPrefix(status.ImageID, "sha256:") {
			imageDigest = status.ImageID
			break
		}
	}
	return Pod{
		Namespace: document.Metadata.Namespace, Name: document.Metadata.Name, UID: document.Metadata.UID,
		NodeName: document.Spec.NodeName, ServiceAccount: document.Spec.ServiceAccountName,
		ImageDigest: imageDigest, Labels: document.Metadata.Labels,
	}, nil
}

type podDocument struct {
	Metadata struct {
		Namespace string            `json:"namespace"`
		Name      string            `json:"name"`
		UID       string            `json:"uid"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName           string `json:"nodeName"`
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses []struct {
			ImageID string `json:"imageID"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func AttestAuthenticated(pid int, resolver AuthenticatedResolver) (attestation.Selectors, error) {
	if resolver == nil || !resolver.Authenticated() {
		return nil, ErrPodUnavailable
	}
	return Attest(pid, resolver)
}

func Attest(pid int, resolver Resolver) (attestation.Selectors, error) {
	if pid <= 0 || resolver == nil {
		return nil, ErrPodUnavailable
	}
	pod, err := resolver.ResolvePID(pid)
	if err != nil || pod.Namespace == "" || pod.ServiceAccount == "" || pod.Name == "" || pod.UID == "" || pod.NodeName == "" || pod.ImageDigest == "" {
		return nil, ErrPodUnavailable
	}
	if len(pod.ImageDigest) < len("sha256:") || pod.ImageDigest[:len("sha256:")] != "sha256:" {
		return nil, ErrPodUnavailable
	}
	selectors := []attestation.Selector{
		{Type: "k8s.ns", Value: pod.Namespace},
		{Type: "k8s.sa", Value: pod.ServiceAccount},
		{Type: "k8s.pod-name", Value: pod.Name},
		{Type: "k8s.pod-uid", Value: pod.UID},
		{Type: "k8s.node-name", Value: pod.NodeName},
		{Type: "k8s.container-image-digest", Value: pod.ImageDigest},
	}
	for key, value := range pod.Labels {
		if key == "" || value == "" {
			return nil, fmt.Errorf("%w: empty pod label", ErrPodUnavailable)
		}
		selectors = append(selectors, attestation.Selector{Type: "k8s.pod-label:" + key, Value: value})
	}
	return attestation.NewSelectors(selectors...)
}
