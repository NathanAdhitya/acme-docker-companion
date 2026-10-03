// Package fsutil provides atomic, durable file writes.
package fsutil

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes data to path atomically and durably:
//
//	temp file in the same directory -> fsync -> rename -> fsync directory.
//
// If the destination already contains exactly the same bytes it is left
// untouched and changed is false. That keeps mtimes stable so file-watching
// targets are not woken for no reason.
func WriteFileAtomic(path string, data []byte, mode os.FileMode, uid, gid int) (changed bool, err error) {
	if existing, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(existing, data) {
		return false, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create dir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// Best-effort cleanup if we fail before the rename.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write temp file %s: %w", tmpName, err)
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("chmod temp file %s: %w", tmpName, err)
	}
	if uid >= 0 || gid >= 0 {
		if err = tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return false, fmt.Errorf("chown temp file %s: %w", tmpName, err)
		}
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("fsync temp file %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp file %s: %w", tmpName, err)
	}

	if err = os.Rename(tmpName, path); err != nil {
		return false, fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	if err = SyncDir(dir); err != nil {
		return false, err
	}
	return true, nil
}

// SyncDir fsyncs a directory so a rename within it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

// CleanTemp removes leftover atomic-write temp files from a directory tree.
// It is called at startup so a crash mid-write cannot accumulate junk.
func CleanTemp(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // ignore unreadable entries
		}
		// Temp files are created as ".<name>.tmp-<random>".
		name := d.Name()
		if !d.IsDir() && strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-") {
			_ = os.Remove(path)
		}
		return nil
	})
}
