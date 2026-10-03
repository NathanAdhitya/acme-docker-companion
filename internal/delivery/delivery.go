// Package delivery resolves where a target container's certificate directory
// lives inside the manager, and writes certificate files there atomically.
package delivery

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/fsutil"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

// Options controls ownership and permissions of written files.
type Options struct {
	UID      int
	GID      int
	CertMode os.FileMode
	KeyMode  os.FileMode
}

// Resolve translates a path inside the target container into the equivalent
// path inside the manager container by matching mount sources.
//
// It returns a descriptive error when the target does not mount a directory
// covering targetPath, or when the manager does not mount the same source.
func Resolve(targetMounts []dockerx.Mount, targetPath string, managerMounts []dockerx.Mount) (string, error) {
	targetPath = path.Clean(targetPath)
	if !path.IsAbs(targetPath) {
		return "", fmt.Errorf("target path %q is not absolute", targetPath)
	}

	best := bestMount(targetMounts, targetPath)
	if best == nil {
		return "", fmt.Errorf("target does not mount a directory covering %s; mount the shared certificate volume into the container", targetPath)
	}
	if best.Source == "" {
		return "", fmt.Errorf("target mount for %s has no host source (tmpfs mounts cannot be written)", targetPath)
	}

	rel := relWithin(best.Destination, targetPath)
	hostPath := path.Join(best.Source, rel)

	mgr := bestMountBySource(managerMounts, hostPath)
	if mgr == nil {
		return "", fmt.Errorf("manager cannot see host path %s (target mount source %q); mount the same volume/directory into the manager or set acmed.manager-path", hostPath, best.Source)
	}
	mgrRel := relWithin(mgr.Source, hostPath)
	return path.Join(mgr.Destination, mgrRel), nil
}

// bestMount returns the most specific mount whose Destination covers p. This
// is used to locate a path inside the target container.
func bestMount(mounts []dockerx.Mount, p string) *dockerx.Mount {
	return mostSpecific(mounts, p, func(m dockerx.Mount) string { return m.Destination })
}

// bestMountBySource returns the most specific mount whose Source covers a host
// path. This is used to locate a host path inside the manager container.
func bestMountBySource(mounts []dockerx.Mount, p string) *dockerx.Mount {
	return mostSpecific(mounts, p, func(m dockerx.Mount) string { return m.Source })
}

func mostSpecific(mounts []dockerx.Mount, p string, base func(dockerx.Mount) string) *dockerx.Mount {
	var best *dockerx.Mount
	bestLen := -1
	for i := range mounts {
		b := base(mounts[i])
		if b == "" {
			continue
		}
		if !within(b, p) {
			continue
		}
		if len(b) > bestLen {
			best = &mounts[i]
			bestLen = len(b)
		}
	}
	return best
}

// within reports whether p is base or lives beneath base.
func within(base, p string) bool {
	base = path.Clean(base)
	p = path.Clean(p)
	if p == base {
		return true
	}
	return strings.HasPrefix(p, base+"/")
}

// relWithin returns the part of p below base ("" when equal).
func relWithin(base, p string) string {
	base = path.Clean(base)
	p = path.Clean(p)
	if p == base {
		return ""
	}
	return strings.TrimPrefix(p, base+"/")
}

// WriteCert writes the certificate files into dir, skipping any file whose
// content is unchanged. changed is true when at least one file was rewritten.
//
// It takes the cached certificate so the delivered copy uses the same file
// names and fields as the cache (DESIGN Appendix B).
func WriteCert(dir string, c *store.Cert, opts Options) (changed bool, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create certificate dir %s: %w", dir, err)
	}
	entries := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{store.FileFullchain, c.Fullchain, opts.CertMode},
		{store.FileCert, c.CertPEM, opts.CertMode},
		{store.FileChain, c.Chain, opts.CertMode},
		{store.FilePrivkey, c.Privkey, opts.KeyMode},
	}
	for _, e := range entries {
		p := path.Join(dir, e.name)
		if len(e.data) == 0 {
			// Nothing to write (e.g. a bundle with no intermediates): remove
			// any stale file left by a previous certificate.
			if _, serr := os.Stat(p); serr == nil {
				if rerr := os.Remove(p); rerr != nil {
					return changed, fmt.Errorf("remove stale %s: %w", p, rerr)
				}
				changed = true
			}
			continue
		}
		c, werr := fsutil.WriteFileAtomic(p, e.data, e.mode, opts.UID, opts.GID)
		if werr != nil {
			return changed, werr
		}
		changed = changed || c
	}
	return changed, nil
}
