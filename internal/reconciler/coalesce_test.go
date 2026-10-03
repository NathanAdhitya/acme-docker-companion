package reconciler

import (
	"context"
	"testing"
)

// TestReloadCoalescedAcrossCertificates: two certificates in one container that
// share a reload action (inherited from the container default) reload once.
func TestReloadCoalescedAcrossCertificates(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.reload.cmd":  "nginx -s reload",
		"acmed.domains":     "example.com",
		"acmed.path":        "/etc/nginx/certs/example.com",
		"acmed.api.domains": "api.example.com",
		"acmed.api.path":    "/etc/nginx/certs/api.example.com",
	}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

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
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.reload.cmd":     "nginx -s reload",
		"acmed.domains":        "example.com",
		"acmed.path":           "/etc/nginx/certs/example.com",
		"acmed.api.domains":    "api.example.com",
		"acmed.api.path":       "/etc/nginx/certs/api.example.com",
		"acmed.api.reload.cmd": "service nginx reload",
	}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	if docker.execCount() != 2 {
		t.Fatalf("distinct reload actions should each run, got %d", docker.execCount())
	}
}

// TestReloadCoalescedSignal covers the signal path.
func TestReloadCoalescedSignal(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.reload.signal": "SIGHUP",
		"acmed.domains":       "example.com",
		"acmed.path":          "/etc/nginx/certs/example.com",
		"acmed.api.domains":   "api.example.com",
		"acmed.api.path":      "/etc/nginx/certs/api.example.com",
	}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	docker.mu.Lock()
	defer docker.mu.Unlock()
	if len(docker.signals) != 1 || docker.signals[0] != "SIGHUP" {
		t.Fatalf("shared signal must be sent once, got %v", docker.signals)
	}
}
