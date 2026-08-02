package secretfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRejectsBroadPermissionsAndSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(target, true, 1024); err == nil {
		t.Fatal("broad secret permissions were accepted")
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(target, true, 1024); err == nil {
		t.Fatal("executable secret permissions were accepted")
	}
	if err := os.Chmod(target, 0o400); err != nil {
		t.Fatal(err)
	}
	readOnly, err := Read(target, true, 1024)
	if err != nil {
		t.Fatalf("mode 0400 Read: %v", err)
	}
	clear(readOnly)
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, true, 1024); err == nil {
		t.Fatal("secret symlink was accepted")
	}
	value, err := Read(target, true, 1024)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer clear(value)
	if string(value) != "value\n" {
		t.Fatalf("value = %q", value)
	}
}

func TestWriteExclusiveUses0600AndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "hash")
	value := []byte("sha256$example")
	if err := WriteExclusive(path, value); err != nil {
		t.Fatalf("WriteExclusive: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := WriteExclusive(path, []byte("replacement")); err == nil {
		t.Fatal("existing secret was overwritten")
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored)
	if string(stored) != "sha256$example\n" {
		t.Fatal("secret file content changed")
	}
}
