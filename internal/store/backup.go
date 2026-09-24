package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupInfo describes a backup file.
type BackupInfo struct {
	Path      string
	Created   time.Time
	Encrypted bool
	Size      int64
	Checksum  string
}

// BackupError is returned when a backup operation fails.
type BackupError struct {
	Operation string
	Cause     error
}

func (e *BackupError) Error() string {
	return fmt.Sprintf("backup %s failed: %v", e.Operation, e.Cause)
}

func (e *BackupError) Unwrap() error {
	return e.Cause
}

// NewBackupError creates a new backup error.
func NewBackupError(operation string, cause error) *BackupError {
	return &BackupError{Operation: operation, Cause: cause}
}

// backupKey derives an AES-256 key from a passphrase.
func backupKey(passphrase []byte) []byte {
	key := sha256.Sum256(passphrase)
	return key[:]
}

// encrypt encrypts data using AES-GCM with a random nonce.
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size for AES-256")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	return combined, nil
}

// decrypt decrypts data encrypted with encrypt.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size for AES-256")
	}
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:12]
	data := ciphertext[12:]
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// backupPool is the minimum interface required to create a backup.
// It allows the backup creation logic to be tested without a real database.
type backupPool interface {
	Config() *pgxpool.Config
}

// CreateBackup creates an encrypted backup of the database.
func CreateBackup(ctx context.Context, pool backupPool, backupDir string, passphrase []byte) (string, error) {
	if pool == nil {
		return "", NewBackupError("create", errors.New("nil pool"))
	}
	if len(passphrase) == 0 {
		return "", NewBackupError("create", errors.New("empty passphrase"))
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", NewBackupError("mkdir", err)
	}
	tmpDir, err := os.MkdirTemp(backupDir, "tmp-*")
	if err != nil {
		return "", NewBackupError("temp", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	dumpPath := filepath.Join(tmpDir, "dump.sql")
	cmd := exec.CommandContext(ctx, "pg_dump", pool.Config().ConnString(), "-F", "c")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", NewBackupError("dump", fmt.Errorf("pg_dump failed: %v: %s", err, stderr.String()))
	}
	if err := os.WriteFile(dumpPath, out.Bytes(), 0o644); err != nil {
		return "", NewBackupError("write", err)
	}
	checksum := sha256.Sum256(out.Bytes())
	compressed := bytes.NewReader(out.Bytes())
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.Copy(gz, compressed); err != nil {
		gz.Close()
		return "", NewBackupError("compress", err)
	}
	if err := gz.Close(); err != nil {
		return "", NewBackupError("compress", err)
	}
	encrypted, err := encrypt(buf.Bytes(), backupKey(passphrase))
	if err != nil {
		return "", NewBackupError("encrypt", err)
	}
	sig := sha256.Sum256(encrypted)
	finalFile := filepath.Join(backupDir, fmt.Sprintf("backup_%d_%s.enc", time.Now().UnixNano(), hex.EncodeToString(sig[:])[:16]))
	if err := os.WriteFile(finalFile, encrypted, 0o600); err != nil {
		return "", NewBackupError("write", err)
	}
	meta := fmt.Sprintf(`{"timestamp":"%s","version":"1","connection":"%s","checksum":"%s","encrypted":true,"size":%d}`, time.Now().UTC().Format(time.RFC3339), pool.Config().ConnString(), hex.EncodeToString(checksum[:]), int64(len(out.Bytes())))
	if err := os.WriteFile(finalFile+".meta", []byte(meta), 0o600); err != nil {
		_ = os.Remove(finalFile)
		return "", NewBackupError("meta", err)
	}
	done = true
	_ = os.RemoveAll(tmpDir)
	return finalFile, nil
}

// RestoreBackup restores a backup from a file.
func RestoreBackup(ctx context.Context, pool *pgxpool.Pool, backupFile string, passphrase []byte) error {
	if pool == nil {
		return NewBackupError("restore", errors.New("nil pool"))
	}
	if len(passphrase) == 0 {
		return NewBackupError("restore", errors.New("empty passphrase"))
	}
	encBytes, err := os.ReadFile(backupFile)
	if err != nil {
		return NewBackupError("read", err)
	}
	plaintext, err := decrypt(encBytes, backupKey(passphrase))
	if err != nil {
		return NewBackupError("decrypt", err)
	}
	tmpDir, err := os.MkdirTemp("", "restore-*")
	if err != nil {
		return NewBackupError("temp", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	dumpPath := filepath.Join(tmpDir, "dump.sql")
	if err := os.WriteFile(dumpPath, plaintext, 0o644); err != nil {
		return NewBackupError("write dump", err)
	}
	cmd := exec.CommandContext(ctx, "pg_restore", "-d", pool.Config().ConnString(), dumpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return NewBackupError("restore", fmt.Errorf("pg_restore failed: %v: %s", err, stderr.String()))
	}
	done = true
	_ = os.RemoveAll(tmpDir)
	return nil
}

// ListBackups lists all backup files in a directory.
func ListBackups(backupDir string) ([]BackupInfo, error) {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, err
	}
	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".enc") || strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		path := filepath.Join(backupDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{Path: path, Created: info.ModTime(), Encrypted: true, Size: info.Size()})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].Created.After(backups[j].Created) })
	return backups, nil
}

// CleanupBackups removes backups older than maxAge or exceeding maxCount.
func CleanupBackups(backupDir string, maxCount int, maxAge time.Duration) error {
	if maxCount <= 0 && maxAge <= 0 {
		return nil
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}
	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".enc") {
			continue
		}
		path := filepath.Join(backupDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{Path: path, Created: info.ModTime(), Encrypted: true, Size: info.Size()})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].Created.Before(backups[j].Created) })
	now := time.Now()
	for _, b := range backups {
		if maxAge > 0 && now.Sub(b.Created) > maxAge {
			if err := os.Remove(b.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.Remove(b.Path + ".meta"); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if maxCount > 0 && len(backups) > maxCount {
		// sort by creation time (oldest first)
		sort.Slice(backups, func(i, j int) bool { return backups[i].Created.Before(backups[j].Created) })
		for i := 0; i < len(backups)-maxCount; i++ {
			b := backups[i]
			if err := os.Remove(b.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.Remove(b.Path + ".meta"); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
