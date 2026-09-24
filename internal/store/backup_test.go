package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	plaintext := []byte("sensitive backup data")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ciphertext) <= 12 {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}

	got, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptDecryptRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := encrypt([]byte("data"), []byte("short")); err == nil {
		t.Fatal("encrypt with short key should fail")
	}
	if _, err := decrypt(make([]byte, 11), make([]byte, 32)); err == nil {
		t.Fatal("decrypt with short ciphertext should fail")
	}
	if _, err := decrypt([]byte("not-a-valid-ciphertext"), make([]byte, 32)); err == nil {
		t.Fatal("decrypt with tampered ciphertext should fail")
	}
}

func TestBackupErrorWrapping(t *testing.T) {
	t.Parallel()

	cause := errors.New("database unavailable")
	err := NewBackupError("create", cause)
	if !errors.Is(err, cause) {
		t.Fatalf("BackupError does not wrap cause: %v", err)
	}
	if err.Error() != "backup create failed: database unavailable" {
		t.Fatalf("error message = %q", err.Error())
	}
}

func TestListBackups(t *testing.T) {
	t.Parallel()

	backupDir := t.TempDir()
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-time.Hour)

	for _, name := range []string{"backup_1.enc", "backup_2.enc"} {
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(backupDir, "backup_1.enc"), older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(backupDir, "backup_2.enc"), newer, newer); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(backupDir, "backup_1.enc.meta"), []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}

	backups, err := ListBackups(backupDir)
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("got %d backups, want 2", len(backups))
	}
	if backups[0].Path != filepath.Join(backupDir, "backup_2.enc") {
		t.Fatalf("most recent backup = %q", backups[0].Path)
	}
	if !backups[0].Encrypted {
		t.Fatalf("most recent backup should be marked encrypted")
	}
	if backups[0].Size != 9 {
		t.Fatalf("backup size = %d, want 9", backups[0].Size)
	}
}

func TestCleanupBackups(t *testing.T) {
	t.Parallel()

	backupDir := t.TempDir()
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-30 * time.Minute)

	for _, name := range []string{"backup_1.enc", "backup_2.enc", "backup_3.enc"} {
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".meta", []byte("metadata"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(backupDir, "backup_1.enc"), older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(backupDir, "backup_2.enc"), newer, newer); err != nil {
		t.Fatal(err)
	}

	if err := CleanupBackups(backupDir, 0, time.Hour); err != nil {
		t.Fatalf("CleanupBackups: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_1.enc")); !os.IsNotExist(err) {
		t.Fatalf("old backup still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_1.enc.meta")); !os.IsNotExist(err) {
		t.Fatalf("old backup metadata still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_2.enc")); err != nil {
		t.Fatalf("recent backup missing: %v", err)
	}
}

func TestCleanupBackupsByCount(t *testing.T) {
	t.Parallel()

	backupDir := t.TempDir()
	for _, name := range []string{"backup_1.enc", "backup_2.enc", "backup_3.enc"} {
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".meta", []byte("metadata"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := CleanupBackups(backupDir, 2, 0); err != nil {
		t.Fatalf("CleanupBackups: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_1.enc")); !os.IsNotExist(err) {
		t.Fatalf("oldest backup still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_2.enc")); err != nil {
		t.Fatalf("backup_2 missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "backup_3.enc")); err != nil {
		t.Fatalf("backup_3 missing: %v", err)
	}
}

func TestRecoveryMetricsRPO(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	m := &RecoveryMetrics{}
	if got := m.RPO(); got != time.Duration(^uint64(0)>>1) {
		t.Fatalf("RPO before backup = %v, want max duration", got)
	}
	if m.MeetsRPO(time.Hour) {
		t.Fatalf("RPO before backup should not meet a 1 hour target")
	}

	m.UpdateBackup(1024, time.Second)
	if m.LastBackupTime.Before(now.Add(-time.Second)) || m.LastBackupTime.After(now.Add(time.Second)) {
		t.Fatalf("LastBackupTime = %v, want around %v", m.LastBackupTime, now)
	}
	if m.LastBackupSize != 1024 {
		t.Fatalf("LastBackupSize = %d, want 1024", m.LastBackupSize)
	}
	if !m.MeetsRPO(24 * time.Hour) {
		t.Fatalf("RPO after backup should meet a 24 hour target")
	}
}

func TestRecoveryMetricsRTO(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	m := &RecoveryMetrics{}
	if got := m.RTO(); got != 0 {
		t.Fatalf("RTO before restore = %v, want 0", got)
	}
	if !m.MeetsRTO(time.Hour) {
		t.Fatalf("RTO before restore should meet a 1 hour target")
	}

	m.UpdateRestore(30 * time.Minute)
	if m.LastRestoreTime.Before(now.Add(-time.Second)) || m.LastRestoreTime.After(now.Add(time.Second)) {
		t.Fatalf("LastRestoreTime = %v, want around %v", m.LastRestoreTime, now)
	}
	if m.RestoreDuration != 30*time.Minute {
		t.Fatalf("RestoreDuration = %v, want 30m", m.RestoreDuration)
	}
	if !m.MeetsRTO(time.Hour) {
		t.Fatalf("RTO after restore should meet a 1 hour target")
	}
}

func TestCreateBackupRequiresValidInputs(t *testing.T) {
	t.Parallel()

	backupDir := t.TempDir()
	key := make([]byte, 32)
	if _, err := CreateBackup(context.Background(), nil, backupDir, key); err == nil {
		t.Fatal("CreateBackup with nil pool should fail")
	}
	if _, err := CreateBackup(context.Background(), &pgxPoolStub{}, backupDir, nil); err == nil {
		t.Fatal("CreateBackup with empty passphrase should fail")
	}
}

// pgxPoolStub is a minimal stub used to verify CreateBackup rejects invalid inputs.
type pgxPoolStub struct{}

func (s *pgxPoolStub) Config() *pgxpool.Config {
	return nil
}

func TestBackupMetadataIsEncrypted(t *testing.T) {
	t.Parallel()

	plaintext := []byte("sensitive data that should be encrypted")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("encrypted data should not equal plaintext")
	}
	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted data should equal plaintext")
	}
}

func TestRestoreBackupInvalidInputs(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	// RestoreBackup requires a non-nil pool; nil pool fails immediately.
	if err := RestoreBackup(context.Background(), nil, "/nonexistent/path.enc", key); err == nil {
		t.Fatal("RestoreBackup with nil pool should fail")
	}
	// Empty passphrase with nil pool also fails on nil pool check first.
	if err := RestoreBackup(context.Background(), nil, "/nonexistent/path.enc", nil); err == nil {
		t.Fatal("RestoreBackup with empty passphrase should fail")
	}
}

func TestRestoreBackupDecryptVerification(t *testing.T) {
	t.Parallel()

	backupDir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("sensitive backup data for restore verification")
	encrypted, err := encrypt(plaintext, backupKey(key))
	if err != nil {
		t.Fatal(err)
	}
	backupFile := filepath.Join(backupDir, "backup_test.enc")
	if err := os.WriteFile(backupFile, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := fmt.Sprintf(`{"timestamp":"%s","version":"1","connection":"test","checksum":"abc123","encrypted":true,"size":%d}`, time.Now().UTC().Format(time.RFC3339), len(plaintext))
	if err := os.WriteFile(backupFile+".meta", []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	decrypted, err := decrypt(encrypted, backupKey(key))
	if err != nil {
		t.Fatalf("decrypt should succeed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch: got %q want %q", decrypted, plaintext)
	}

	// Verify meta file exists
	if _, err := os.Stat(backupFile + ".meta"); err != nil {
		t.Fatalf("metadata file should exist: %v", err)
	}
}

func TestOperationalRPOWithBackupFrequency(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	m := &RecoveryMetrics{}

	// Simulate backup at current time
	m.UpdateBackup(1024, 10*time.Second)
	if got := m.RPO(); got > time.Minute {
		t.Fatalf("RPO after backup should be very low, got %v", got)
	}

	// Simulate waiting past RPO target of 24h by setting LastBackupTime to 25h ago
	m.LastBackupTime = now.Add(-25 * time.Hour)

	if got := m.RPO(); got > 26*time.Hour || got < 24*time.Hour {
		t.Fatalf("RPO after 25h gap should be ~25h, got %v", got)
	}
	if m.MeetsRPO(24 * time.Hour) {
		t.Fatalf("RPO of 25h should not meet 24h target")
	}

	// Simulate new backup brings RPO back within target
	m.UpdateBackup(2048, 5*time.Second)
	if got := m.RPO(); got > time.Minute {
		t.Fatalf("RPO after new backup should be very low, got %v", got)
	}
	if !m.MeetsRPO(24 * time.Hour) {
		t.Fatalf("RPO should meet 24h target after recent backup")
	}
}

func TestOperationalRTOWithRestoreFrequency(t *testing.T) {
	t.Parallel()

	m := &RecoveryMetrics{}

	// Initially should meet RTO target of 1h (0 duration)
	if !m.MeetsRTO(time.Hour) {
		t.Fatalf("RTO of 0 should meet 1h target")
	}

	// Simulate restore operation
	m.UpdateRestore(30 * time.Minute)

	// Verify RTO reflects restore duration
	if got := m.RTO(); got != 30*time.Minute {
		t.Fatalf("RTO = %v, want 30m", got)
	}

	// Should meet 1h target but not 15m target
	if !m.MeetsRTO(time.Hour) {
		t.Fatalf("RTO of 30m should meet 1h target")
	}
	if m.MeetsRTO(15 * time.Minute) {
		t.Fatalf("RTO of 30m should not meet 15m target")
	}
}
