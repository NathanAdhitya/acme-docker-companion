package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "file.pem")

	changed, err := WriteFileAtomic(p, []byte("one"), 0o600, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first write should be changed")
	}

	changed, err = WriteFileAtomic(p, []byte("one"), 0o600, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical content should not be rewritten")
	}

	changed, err = WriteFileAtomic(p, []byte("two"), 0o644, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("different content should be rewritten")
	}
	data, _ := os.ReadFile(p)
	if string(data) != "two" {
		t.Fatalf("content = %q", data)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestCleanTemp(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "fullchain.pem")
	junk := filepath.Join(dir, ".fullchain.pem.tmp-123456")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(junk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CleanTemp(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Error("temp file should have been removed")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("real file should have been kept")
	}
}
