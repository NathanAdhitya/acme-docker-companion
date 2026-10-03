package reconciler

import (
	"context"
	"testing"

	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

// TestReloadCoalescedAcrossCertificates: two certificates in one container that
// share a reload action (inherited from the container default) reload once.
func TestReloadCoalescedAcrossCertificates(t *testing.T) {
	hostSource := t.TempDir()
	managerRoot := t.TempDir()
	caURL := "https://acme-staging-v02.api.letsencrypt.org/directory"

	cfg := testConfig(t, caURL)
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	container := dockerx.Container{
		ID: "c1", Name: "web",
		Labels: map[string]string{
			"acmed.reload.cmd":  "nginx -s reload",
			"acmed.domains":     "example.com",
			"acmed.path":        "/etc/nginx/certs/example.com",
			"acmed.api.domains": "api.example.com",
			"acmed.api.path":    "/etc/nginx/certs/api.example.com",
		},
		Mounts: []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: hostSource}},
	}
	docker := &fakeDocker{
		containers: []dockerx.Container{container},
		self:       dockerx.Container{ID: "self", Mounts: []dockerx.Mount{{Destination: managerRoot, Source: hostSource}}},
		selfOK:     true,
	}
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, caURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	snap := rec.Snapshot()
	if len(snap.Certs) != 2 {
		t.Fatalf("want 2 certificates, got %d", len(snap.Certs))
	}
	for _, c := range snap.Certs {
		if len(c.Targets) != 1 || c.Targets[0].Reload != "ok" {
			t.Fatalf("cert %s target = %+v", c.ID, c.Targets)
		}
	}
	if docker.execCount() != 1 {
		t.Fatalf("shared reload action must run once, got %d executions", docker.execCount())
	}
}

// TestReloadDistinctActionsNotCoalesced: different per-certificate reload
// commands each run.
func TestReloadDistinctActionsNotCoalesced(t *testing.T) {
	hostSource := t.TempDir()
	managerRoot := t.TempDir()
	caURL := "https://acme-staging-v02.api.letsencrypt.org/directory"

	cfg := testConfig(t, caURL)
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	container := dockerx.Container{
		ID: "c1", Name: "web",
		Labels: map[string]string{
			"acmed.reload.cmd":     "nginx -s reload",
			"acmed.domains":        "example.com",
			"acmed.path":           "/etc/nginx/certs/example.com",
			"acmed.api.domains":    "api.example.com",
			"acmed.api.path":       "/etc/nginx/certs/api.example.com",
			"acmed.api.reload.cmd": "service nginx reload",
		},
		Mounts: []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: hostSource}},
	}
	docker := &fakeDocker{
		containers: []dockerx.Container{container},
		self:       dockerx.Container{ID: "self", Mounts: []dockerx.Mount{{Destination: managerRoot, Source: hostSource}}},
		selfOK:     true,
	}
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, caURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	if docker.execCount() != 2 {
		t.Fatalf("distinct reload actions should each run, got %d", docker.execCount())
	}
}

// TestReloadCoalescedSignal covers the signal path.
func TestReloadCoalescedSignal(t *testing.T) {
	hostSource := t.TempDir()
	managerRoot := t.TempDir()
	caURL := "https://acme-staging-v02.api.letsencrypt.org/directory"

	cfg := testConfig(t, caURL)
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	container := dockerx.Container{
		ID: "c1", Name: "web",
		Labels: map[string]string{
			"acmed.reload.signal": "SIGHUP",
			"acmed.domains":       "example.com",
			"acmed.path":          "/etc/nginx/certs/example.com",
			"acmed.api.domains":   "api.example.com",
			"acmed.api.path":      "/etc/nginx/certs/api.example.com",
		},
		Mounts: []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: hostSource}},
	}
	docker := &fakeDocker{
		containers: []dockerx.Container{container},
		self:       dockerx.Container{ID: "self", Mounts: []dockerx.Mount{{Destination: managerRoot, Source: hostSource}}},
		selfOK:     true,
	}
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, caURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	docker.mu.Lock()
	defer docker.mu.Unlock()
	if len(docker.signals) != 1 || docker.signals[0] != "SIGHUP" {
		t.Fatalf("shared signal must be sent once, got %v", docker.signals)
	}
}
