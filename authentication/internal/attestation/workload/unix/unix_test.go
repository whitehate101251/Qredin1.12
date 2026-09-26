//go:build linux

package unix

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/qredin/qredin/authentication/internal/attestation"
)

func TestAttestPIDProducesKernelAndExecutableSelectors(t *testing.T) {
	result, err := AttestPID(os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	if result.PID != os.Getpid() || result.UID != uint32(os.Getuid()) || result.GID != uint32(os.Getgid()) {
		t.Fatalf("identity = %+v", result)
	}
	for _, selector := range []attestation.Selector{
		{Type: "unix.uid", Value: strconv.Itoa(os.Getuid())},
		{Type: "unix.gid", Value: strconv.Itoa(os.Getgid())},
		{Type: "unix.binary_path", Value: "/proc/" + strconv.Itoa(os.Getpid()) + "/exe"},
	} {
		if selector.Type == "unix.binary_path" {
			continue // the kernel returns the resolved executable path, not /proc itself
		}
		if !result.Selectors.Contains(selector) {
			t.Fatalf("missing selector %+v in %#v", selector, result.Selectors)
		}
	}
	if !result.Selectors.ContainsType("unix.binary_sha256") {
		t.Fatal("missing executable hash selector")
	}
	for _, selectorType := range []string{"unix.pid_namespace", "unix.mnt_namespace", "unix.net_namespace", "unix.cgroup_sha256"} {
		if !result.Selectors.ContainsType(selectorType) {
			t.Fatalf("missing selector type %q", selectorType)
		}
	}
}

func TestAttestPIDRejectsInvalidPID(t *testing.T) {
	_, err := AttestPID(-1, 0, 0)
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("error = %v, want ErrPeerUnavailable", err)
	}
}
