package kubernetes_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qredin/qredin/authentication/internal/attestation/workload/kubernetes"
)

func TestHTTPResolverUsesAuthenticatedHTTPSPodAPI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer projected-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"namespace": "payments", "name": "api-1", "uid": "pod-1", "labels": map[string]string{"role": "api"}},
			"spec":     map[string]any{"nodeName": "node-1", "serviceAccountName": "api"},
			"status":   map[string]any{"containerStatuses": []map[string]string{{"imageID": "sha256:abc"}}},
		})
	}))
	defer server.Close()
	resolver, err := kubernetes.NewHTTPResolver(server.URL, "projected-token", pidMapper{}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !resolver.Authenticated() {
		t.Fatal("resolver is not authenticated")
	}
	pod, err := resolver.ResolvePID(42)
	if err != nil || pod.ImageDigest != "sha256:abc" || pod.Namespace != "payments" {
		t.Fatalf("pod = %+v, %v", pod, err)
	}
}

type pidMapper struct{}

func (pidMapper) PodForPID(int) (string, string, error) { return "payments", "api-1", nil }
