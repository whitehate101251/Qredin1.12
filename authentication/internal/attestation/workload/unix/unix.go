//go:build linux

// Package unix implements workload attestation for Linux Unix-domain sockets.
package unix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/qredin/qredin/authentication/internal/attestation"
)

var (
	ErrPeerUnavailable = errors.New("unix attestation: peer credentials unavailable")
	ErrPIDReused       = errors.New("unix attestation: peer PID was reused during attestation")
)

// Result is the trusted identity evidence derived from the kernel and procfs.
type Result struct {
	PID       int
	UID       uint32
	GID       uint32
	Selectors attestation.Selectors
}

// AttestUnixConn obtains the peer PID, UID, and GID from SO_PEERCRED. It never
// accepts identity or selector claims from the socket client.
func AttestUnixConn(conn *net.UnixConn) (Result, error) {
	if conn == nil {
		return Result{}, ErrPeerUnavailable
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return Result{}, fmt.Errorf("unix attestation: obtaining socket: %w", err)
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Result{}, fmt.Errorf("unix attestation: accessing socket: %w", err)
	}
	if controlErr != nil || credentials == nil {
		return Result{}, ErrPeerUnavailable
	}
	return AttestPID(int(credentials.Pid), credentials.Uid, credentials.Gid)
}

// AttestPID is exposed for the node agent's socket adapter and deterministic
// tests. uid/gid still come from SO_PEERCRED in normal operation.
func AttestPID(pid int, uid, gid uint32) (Result, error) {
	if pid <= 0 {
		return Result{}, ErrPeerUnavailable
	}
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	proc, err := os.Open(procDir)
	if err != nil {
		return Result{}, fmt.Errorf("unix attestation: opening proc entry: %w", err)
	}
	defer proc.Close()

	startBefore, err := processStartTime(procDir)
	if err != nil {
		return Result{}, err
	}
	selectors := []attestation.Selector{
		{Type: "unix.uid", Value: strconv.FormatUint(uint64(uid), 10)},
		{Type: "unix.gid", Value: strconv.FormatUint(uint64(gid), 10)},
	}
	groups, err := supplementaryGroups(procDir)
	if err != nil {
		return Result{}, err
	}
	for _, group := range groups {
		selectors = append(selectors, attestation.Selector{Type: "unix.supplementary_gid", Value: group})
	}
	namespaceSelectors, err := namespaceSelectors(procDir)
	if err != nil {
		return Result{}, err
	}
	selectors = append(selectors, namespaceSelectors...)
	cgroupDigest, err := cgroupDigest(procDir)
	if err != nil {
		return Result{}, err
	}
	selectors = append(selectors, attestation.Selector{Type: "unix.cgroup_sha256", Value: cgroupDigest})
	exe, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil {
		return Result{}, fmt.Errorf("unix attestation: resolving executable: %w", err)
	}
	selectors = append(selectors, attestation.Selector{Type: "unix.binary_path", Value: exe})
	hash, err := hashExecutable(exe)
	if err != nil {
		return Result{}, err
	}
	selectors = append(selectors, attestation.Selector{Type: "unix.binary_sha256", Value: hash})

	startAfter, err := processStartTime(procDir)
	if err != nil {
		return Result{}, err
	}
	if startBefore != startAfter {
		return Result{}, ErrPIDReused
	}
	verified, err := attestation.NewSelectors(selectors...)
	if err != nil {
		return Result{}, fmt.Errorf("unix attestation: validating selectors: %w", err)
	}
	return Result{PID: pid, UID: uid, GID: gid, Selectors: verified}, nil
}

func namespaceSelectors(procDir string) ([]attestation.Selector, error) {
	selectors := make([]attestation.Selector, 0, 3)
	for _, namespace := range []string{"pid", "mnt", "net"} {
		value, err := os.Readlink(filepath.Join(procDir, "ns", namespace))
		if err != nil {
			return nil, fmt.Errorf("unix attestation: reading %s namespace: %w", namespace, err)
		}
		selectors = append(selectors, attestation.Selector{Type: "unix." + namespace + "_namespace", Value: value})
	}
	return selectors, nil
}

func cgroupDigest(procDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err != nil {
		return "", fmt.Errorf("unix attestation: reading cgroup: %w", err)
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash[:]), nil
}

func processStartTime(procDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return "", fmt.Errorf("unix attestation: reading process stat: %w", err)
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 {
		return "", errors.New("unix attestation: malformed process stat")
	}
	fields := strings.Fields(string(data)[closeParen+1:])
	// The suffix starts at field 3, so field 22 is index 19.
	if len(fields) <= 19 {
		return "", errors.New("unix attestation: process stat has no start time")
	}
	return fields[19], nil
}

func supplementaryGroups(procDir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return nil, fmt.Errorf("unix attestation: reading process status: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Groups:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Groups:"))
		return fields, nil
	}
	return nil, errors.New("unix attestation: process status has no supplementary groups")
}

func hashExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("unix attestation: opening executable: %w", err)
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("unix attestation: hashing executable: %w", err)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
