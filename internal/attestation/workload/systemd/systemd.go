// Package systemd implements workload attestation for systemd services.
package systemd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qredin/qredin/internal/attestation"
)

var ErrUnitUnavailable = errors.New("systemd attestation: unit unavailable")

// Resolver supplies unit metadata from the node's systemd/proc view.
type Resolver interface {
	UnitForPID(pid int) (unit string, fragmentPath string, err error)
}

// ProcResolver derives the unit from procfs and resolves its fragment from
// systemd's node-local unit directories.
type ProcResolver struct{}

func (ProcResolver) UnitForPID(pid int) (string, string, error) {
	if pid <= 0 {
		return "", "", ErrUnitUnavailable
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", "", fmt.Errorf("systemd attestation: reading cgroup: %w", err)
	}
	var unit string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		candidate := filepath.Base(parts[2])
		if strings.HasSuffix(candidate, ".service") || strings.HasSuffix(candidate, ".socket") {
			unit = candidate
			break
		}
	}
	if unit == "" {
		return "", "", ErrUnitUnavailable
	}
	for _, root := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"} {
		path := filepath.Join(root, unit)
		if _, err := os.Stat(path); err == nil {
			return unit, path, nil
		}
	}
	return "", "", ErrUnitUnavailable
}

// Attest resolves only node-local service metadata; no caller-supplied unit
// name participates in the result.
func Attest(pid int, resolver Resolver) (attestation.Selectors, error) {
	if resolver == nil {
		return nil, ErrUnitUnavailable
	}
	unit, fragment, err := resolver.UnitForPID(pid)
	if err != nil || unit == "" || fragment == "" {
		return nil, ErrUnitUnavailable
	}
	fragmentHash, err := fileDigest(fragment)
	if err != nil {
		return nil, ErrUnitUnavailable
	}
	return attestation.NewSelectors(
		attestation.Selector{Type: "systemd.unit", Value: unit},
		attestation.Selector{Type: "systemd.unit_fragment_path", Value: fragment},
		attestation.Selector{Type: "systemd.unit_fragment_sha256", Value: fragmentHash},
	)
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("systemd attestation: opening fragment: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("systemd attestation: hashing fragment: %w", err)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}
