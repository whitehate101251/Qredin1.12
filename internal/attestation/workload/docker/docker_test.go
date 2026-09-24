package docker_test

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/qredin/qredin/internal/attestation"
	"github.com/qredin/qredin/internal/attestation/workload/docker"
)

func TestAttestUsesDigestAndLabels(t *testing.T) {
	selectors, err := docker.Attest(12, fakeInspector{})
	if err != nil {
		t.Fatal(err)
	}
	if !selectors.Contains(attestation.Selector{Type: "docker.image_digest", Value: "sha256:abc"}) {
		t.Fatal("missing image digest selector")
	}
	if !selectors.Contains(attestation.Selector{Type: "docker.label:qredin.role", Value: "api"}) {
		t.Fatal("missing label selector")
	}
}

func TestAttestRejectsMutableImageTag(t *testing.T) {
	if _, err := docker.Attest(12, tagInspector{}); !errors.Is(err, docker.ErrMetadataUnavailable) {
		t.Fatalf("error = %v, want ErrMetadataUnavailable", err)
	}
}

func TestSocketInspectorUsesLocalDockerSocketAndDigest(t *testing.T) {
	socketPath := t.TempDir() + "/docker.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{\"RepoDigests\":[\"qredin/api@sha256:abc\"],\"Config\":{\"Labels\":{}}}")
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	inspector, err := docker.NewSocketInspector(socketPath, resolver{})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := inspector.InspectPID(42)
	if err != nil || metadata.ImageID != "sha256:abc" {
		t.Fatalf("metadata = %+v, %v", metadata, err)
	}
}

type fakeInspector struct{}

func (fakeInspector) InspectPID(int) (docker.Metadata, error) {
	return docker.Metadata{ImageID: "sha256:abc", Labels: map[string]string{"qredin.role": "api"}}, nil
}

type tagInspector struct{}

func (tagInspector) InspectPID(int) (docker.Metadata, error) {
	return docker.Metadata{ImageID: "qredin/api:latest"}, nil
}

type resolver struct{}

func (resolver) ContainerIDForPID(int) (string, error) { return "container-1", nil }
