package delivery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

func TestResolveBindMount(t *testing.T) {
	target := []dockerx.Mount{
		{Destination: "/etc/nginx/certs", Source: "/host/certs"},
		{Destination: "/etc/nginx", Source: "/host/nginx"},
	}
	manager := []dockerx.Mount{
		{Destination: "/certs", Source: "/host/certs"},
	}
	got, err := Resolve(target, "/etc/nginx/certs/example.com", manager)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/certs/example.com" {
		t.Errorf("got %q, want /certs/example.com", got)
	}
}

func TestResolveLongestPrefixWins(t *testing.T) {
	target := []dockerx.Mount{
		{Destination: "/etc/nginx", Source: "/host/nginx"},
		{Destination: "/etc/nginx/certs", Source: "/host/certs"},
	}
	manager := []dockerx.Mount{
		{Destination: "/nginx", Source: "/host/nginx"},
		{Destination: "/certs", Source: "/host/certs"},
	}
	got, err := Resolve(target, "/etc/nginx/certs/example.com", manager)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/certs/example.com" {
		t.Errorf("got %q, want /certs/example.com", got)
	}
}

func TestResolveNamedVolume(t *testing.T) {
	src := "/var/lib/docker/volumes/acme-certs/_data"
	target := []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: src}}
	manager := []dockerx.Mount{{Destination: "/certs", Source: src}}
	got, err := Resolve(target, "/etc/nginx/certs/example.com", manager)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/certs/example.com" {
		t.Errorf("got %q", got)
	}
}

func TestResolveErrors(t *testing.T) {
	manager := []dockerx.Mount{{Destination: "/certs", Source: "/host/certs"}}

	// Target does not mount the path.
	if _, err := Resolve(nil, "/etc/nginx/certs/example.com", manager); err == nil {
		t.Error("expected error when the target has no covering mount")
	}
	// Manager cannot see the source.
	target := []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: "/other/certs"}}
	if _, err := Resolve(target, "/etc/nginx/certs/example.com", manager); err == nil {
		t.Error("expected error when the manager cannot see the host path")
	}
	// tmpfs has no source.
	target = []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: ""}}
	if _, err := Resolve(target, "/etc/nginx/certs/example.com", manager); err == nil {
		t.Error("expected error for a tmpfs mount")
	}
}

func TestWriteCertSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	c := &store.Cert{
		Fullchain: []byte("chain"),
		Privkey:   []byte("key"),
		CertPEM:   []byte("cert"),
		Chain:     []byte("issuer"),
	}
	opts := Options{UID: -1, GID: -1, CertMode: 0o644, KeyMode: 0o600}

	changed, err := WriteCert(dir, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first write should report changed")
	}

	changed, err = WriteCert(dir, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical write should not report changed")
	}

	// Key file must use the key mode.
	info, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("privkey mode = %v", info.Mode().Perm())
	}

	c.Privkey = []byte("newkey")
	changed, err = WriteCert(dir, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed key should report changed")
	}
}

// TestWriteCertRemovesStaleChain: a certificate whose bundle has no
// intermediates must not leave the previous chain.pem behind.
func TestWriteCertRemovesStaleChain(t *testing.T) {
	dir := t.TempDir()
	opts := Options{UID: -1, GID: -1, CertMode: 0o644, KeyMode: 0o600}
	c := &store.Cert{
		Fullchain: []byte("chain"),
		Privkey:   []byte("key"),
		CertPEM:   []byte("cert"),
		Chain:     []byte("issuer"),
	}
	if _, err := WriteCert(dir, c, opts); err != nil {
		t.Fatal(err)
	}

	c.Chain = nil
	c.Fullchain = []byte("chain2")
	c.CertPEM = []byte("cert2")
	changed, err := WriteCert(dir, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removing a stale file should report changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "chain.pem")); !os.IsNotExist(err) {
		t.Fatalf("stale chain.pem should have been removed (stat err=%v)", err)
	}
}
