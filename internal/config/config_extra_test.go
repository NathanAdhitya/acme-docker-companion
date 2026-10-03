package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDryRunForcesStagingAndSeparateState(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "letsencrypt")
	t.Setenv("STATE_DIR", "/data")

	cfg, _, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DryRun || !cfg.Staging {
		t.Fatalf("dry-run=%v staging=%v", cfg.DryRun, cfg.Staging)
	}
	if cfg.StateDir != filepath.Join("/data", "dryrun") {
		t.Fatalf("state dir = %q", cfg.StateDir)
	}
	if cfg.CAs["letsencrypt"].Environment != EnvStaging {
		t.Fatalf("CA env = %q", cfg.CAs["letsencrypt"].Environment)
	}
}

func TestFileConventionForRuntimeVars(t *testing.T) {
	clearACMEEnv(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "state")
	if err := os.WriteFile(secret, []byte("/var/lib/acmed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("STATE_DIR_FILE", secret)

	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != "/var/lib/acmed" {
		t.Fatalf("state dir = %q, want the _FILE value", cfg.StateDir)
	}
}

func TestHTTPAddrHonorsFileConvention(t *testing.T) {
	clearACMEEnv(t)
	dir := t.TempDir()
	addr := filepath.Join(dir, "addr")
	if err := os.WriteFile(addr, []byte(":9191\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_ADDR_FILE", addr)
	if got := HTTPAddr(); got != ":9191" {
		t.Fatalf("HTTPAddr() = %q, want :9191", got)
	}
}

// TestUnreadableEABSecretFailsFast: an EAB HMAC configured through _FILE but
// unreadable is a fatal configuration error, not a silent downgrade to a
// registration without EAB (DESIGN §7).
func TestUnreadableEABSecretFailsFast(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_LETSENCRYPT_EAB_HMAC_FILE", filepath.Join(t.TempDir(), "missing"))

	if _, _, err := Load(false); err == nil {
		t.Fatal("expected Load to fail fast when the EAB secret file is unreadable")
	}
}

func TestPrivateCAAndDNSOptions(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "pebble")
	t.Setenv("ACME_PEBBLE_URL", "https://localhost:14000/dir")
	t.Setenv("ACME_CA_SERVER_NAME", "localhost")
	t.Setenv("ACME_DNS_DISABLE_AUTHORITATIVE_CHECK", "true")
	t.Setenv("ACME_DNS_PROPAGATION_WAIT", "2s")

	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAServerName != "localhost" {
		t.Errorf("server name = %q", cfg.CAServerName)
	}
	if !cfg.DNSDisableAuthoritativeCheck {
		t.Error("authoritative check should be disabled")
	}
	if cfg.DNSPropagationWait != 2*time.Second {
		t.Errorf("propagation wait = %v", cfg.DNSPropagationWait)
	}
	if cfg.CAs["pebble"].Environment != EnvCustom {
		t.Errorf("CA env = %q", cfg.CAs["pebble"].Environment)
	}
}
