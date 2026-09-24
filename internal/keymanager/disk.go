package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// DiskManager stores PKCS#8 keys in a dedicated directory. It is intended for
// non-production and explicitly approved air-gapped deployments; AWS KMS is
// the production default.
type DiskManager struct {
	mu         sync.RWMutex
	dir        string
	production bool
	opened     bool
}

func NewDiskManager(dir string) (*DiskManager, error) {
	if dir == "" {
		return nil, errors.New("keymanager: disk directory is required")
	}
	return &DiskManager{dir: filepath.Clean(dir)}, nil
}

func (m *DiskManager) Open(_ context.Context, environment Environment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if environment == EnvironmentProduction && isTemporaryPath(m.dir) {
		return fmt.Errorf("%w: disk key directory is under /tmp", ErrNotProductionSafe)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("keymanager: creating key directory: %w", err)
	}
	if err := os.Chmod(m.dir, 0o700); err != nil {
		return fmt.Errorf("keymanager: securing key directory: %w", err)
	}
	if err := verifyDirectory(m.dir); err != nil {
		return err
	}
	m.production = environment == EnvironmentProduction
	m.opened = true
	return nil
}

func (m *DiskManager) Generate(_ context.Context, spec KeySpec) (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.opened {
		return Key{}, errors.New("keymanager: disk manager is not open")
	}
	if spec.Algorithm != "" && spec.Algorithm != "ECDSA_P256" {
		return Key{}, fmt.Errorf("keymanager: unsupported disk key algorithm %q", spec.Algorithm)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("keymanager: generating disk key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return Key{}, fmt.Errorf("keymanager: encoding disk key: %w", err)
	}
	for attempts := 0; attempts < 3; attempts++ {
		id, err := randomKeyID()
		if err != nil {
			return Key{}, err
		}
		file, err := os.OpenFile(filepath.Join(m.dir, id+".pk8"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return Key{}, fmt.Errorf("keymanager: creating disk key file: %w", err)
		}
		if err = func() error {
			defer file.Close()
			if err := verifyFile(file.Name()); err != nil {
				return err
			}
			if _, err := file.Write(der); err != nil {
				return err
			}
			return file.Sync()
		}(); err != nil {
			_ = os.Remove(file.Name())
			return Key{}, fmt.Errorf("keymanager: writing disk key: %w", err)
		}
		return Key{ID: id, Public: private.Public()}, nil
	}
	return Key{}, errors.New("keymanager: could not allocate a unique disk key ID")
}

func (m *DiskManager) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.opened {
		return nil, errors.New("keymanager: disk manager is not open")
	}
	path := filepath.Join(m.dir, filepath.Base(keyID)+".pk8")
	if filepath.Base(keyID) != keyID {
		return nil, errors.New("keymanager: invalid disk key ID")
	}
	if err := verifyFile(path); err != nil {
		return nil, err
	}
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keymanager: reading disk key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keymanager: parsing disk key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("keymanager: disk key is not a signer")
	}
	return signer, nil
}

func verifyDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keymanager: stating key directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("keymanager: key directory must be a directory with mode 0700")
	}
	return verifyOwner(path, info)
}

func verifyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keymanager: stating key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("keymanager: key file must be regular with mode 0600")
	}
	return verifyOwner(path, info)
}

func verifyOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("keymanager: %s is not owned by the running user", path)
	}
	return nil
}

func isTemporaryPath(path string) bool {
	clean := filepath.Clean(path)
	return clean == "/tmp" || len(clean) > len("/tmp/") && clean[:len("/tmp/")] == "/tmp/"
}

func randomKeyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("keymanager: generating key ID: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
