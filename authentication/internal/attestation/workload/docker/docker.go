// Package docker implements Docker workload selector attestation.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/qredin/qredin/authentication/internal/attestation"
)

var ErrMetadataUnavailable = errors.New("docker attestation: metadata unavailable")

// Metadata is the node-local Docker result for a PID. ImageID must be an
// immutable digest; mutable image tags are intentionally not represented.
type Metadata struct {
	ImageID string
	Labels  map[string]string
}

type Inspector interface {
	InspectPID(pid int) (Metadata, error)
}

// PIDResolver maps a peer PID to a container ID using node-local runtime
// state. It must not be backed by workload-supplied metadata.
type PIDResolver interface {
	ContainerIDForPID(pid int) (string, error)
}

// SocketInspector reads Docker metadata through a node-local Unix socket.
// Network Docker endpoints are intentionally unsupported.
type SocketInspector struct {
	socketPath string
	resolver   PIDResolver
	client     *http.Client
}

func NewSocketInspector(socketPath string, resolver PIDResolver) (*SocketInspector, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) || resolver == nil {
		return nil, ErrMetadataUnavailable
	}
	info, err := os.Stat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o007 != 0 {
		return nil, ErrMetadataUnavailable
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socketPath)
	}}
	return &SocketInspector{
		socketPath: socketPath,
		resolver:   resolver,
		client:     &http.Client{Transport: transport},
	}, nil
}

func (s *SocketInspector) InspectPID(pid int) (Metadata, error) {
	containerID, err := s.resolver.ContainerIDForPID(pid)
	if err != nil || containerID == "" {
		return Metadata{}, ErrMetadataUnavailable
	}
	path := "/containers/" + url.PathEscape(containerID) + "/json"
	request, err := http.NewRequest(http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return Metadata{}, ErrMetadataUnavailable
	}
	response, err := s.client.Do(request)
	if err != nil {
		return Metadata{}, ErrMetadataUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("%w: Docker returned HTTP %d", ErrMetadataUnavailable, response.StatusCode)
	}
	var inspected struct {
		RepoDigests []string `json:"RepoDigests"`
		Config      struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(response.Body).Decode(&inspected); err != nil {
		return Metadata{}, ErrMetadataUnavailable
	}
	for _, digest := range inspected.RepoDigests {
		if index := len(digest); index > len("sha256:") {
			for i := len(digest) - len("sha256:"); i >= 0; i-- {
				if digest[i:i+len("sha256:")] == "sha256:" {
					return Metadata{ImageID: digest[i:], Labels: inspected.Config.Labels}, nil
				}
			}
		}
	}
	return Metadata{}, ErrMetadataUnavailable
}

func Attest(pid int, inspector Inspector) (attestation.Selectors, error) {
	if pid <= 0 || inspector == nil {
		return nil, ErrMetadataUnavailable
	}
	metadata, err := inspector.InspectPID(pid)
	if err != nil || metadata.ImageID == "" {
		return nil, ErrMetadataUnavailable
	}
	if len(metadata.ImageID) < len("sha256:") || metadata.ImageID[:len("sha256:")] != "sha256:" {
		return nil, ErrMetadataUnavailable
	}
	selectors := []attestation.Selector{{Type: "docker.image_digest", Value: metadata.ImageID}}
	for key, value := range metadata.Labels {
		selectors = append(selectors, attestation.Selector{Type: "docker.label:" + key, Value: value})
	}
	return attestation.NewSelectors(selectors...)
}
