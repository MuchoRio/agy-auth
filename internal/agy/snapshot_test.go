package agy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotVaultRoundTrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "encryption.key")
	vault := NewSnapshotVault(keyPath)
	raw := []byte(`{"token":{"refresh_token":"secret-refresh"}}`)
	encoded, err := vault.Encode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret-refresh")) {
		t.Fatalf("ciphertext contains plaintext: %q", encoded)
	}
	if !vault.IsEncrypted(encoded) {
		t.Fatal("encoded value is not marked encrypted")
	}
	second, err := vault.Encode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded, second) {
		t.Fatal("nonce was reused")
	}
	decoded, err := vault.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("decoded = %q", decoded)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key permissions = %o", info.Mode().Perm())
	}
	keyDir, err := os.Stat(filepath.Dir(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if keyDir.Mode().Perm() != 0o700 {
		t.Errorf("key directory permissions = %o", keyDir.Mode().Perm())
	}
}

func TestSnapshotVaultPlaintextAndMissingKey(t *testing.T) {
	vault := NewSnapshotVault(filepath.Join(t.TempDir(), "encryption.key"))
	raw := []byte(`{"token":{"refresh_token":"legacy"}}`)
	decoded, err := vault.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("plaintext changed: %q", decoded)
	}
	encoded, err := vault.Encode(raw)
	if err != nil {
		t.Fatal(err)
	}
	missing := NewSnapshotVault(filepath.Join(t.TempDir(), "missing.key"))
	if _, err := missing.Decode(encoded); err == nil {
		t.Fatal("decrypting without the key succeeded")
	}
	corrupt := append([]byte(snapshotPrefix), []byte("not-base64")...)
	if _, err := vault.Decode(corrupt); err == nil {
		t.Fatal("corrupt ciphertext succeeded")
	}
}

func TestSnapshotVaultRefusesKeyRegenerationWhenEncryptedDataExists(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "encryption.key")
	vault := NewSnapshotVault(keyPath)
	encoded, err := vault.Encode([]byte(`{"token":{"refresh_token":"r1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	accountsDir := filepath.Join(root, "accounts")
	if err := os.MkdirAll(accountsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accountsDir, "acct_1234567890.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Encode([]byte(`{"token":{"refresh_token":"r2"}}`)); !errors.Is(err, ErrSnapshotKey) {
		t.Fatalf("expected ErrSnapshotKey when encrypted snapshots already exist, got %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected key file to remain absent, stat err = %v", err)
	}
}

func TestSnapshotVaultRecoversStaleLock(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "encryption.key")
	lockPath := keyPath + ".lock"
	if err := os.MkdirAll(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-20 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}
	vault := NewSnapshotVault(keyPath)
	if _, err := vault.Encode([]byte(`{"token":{"refresh_token":"r1"}}`)); err != nil {
		t.Fatalf("expected stale lock recovery to succeed, got %v", err)
	}
}
