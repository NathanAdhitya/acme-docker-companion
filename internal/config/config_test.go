package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clearACMEEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		key := strings.SplitN(kv, "=", 2)[0]
		if strings.HasPrefix(key, "ACME_") || strings.HasPrefix(key, "LABEL_") ||
			strings.HasPrefix(key, "STATE_") || strings.HasPrefix(key, "CHECK_") {
			t.Setenv(key, "")
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CAOrder) != 1 || cfg.CAOrder[0] != "letsencrypt" {
		t.Fatalf("CAOrder = %v", cfg.CAOrder)
	}
	if cfg.CAs["letsencrypt"].Environment != EnvProduction {
		t.Errorf("letsencrypt should be production")
	}
	if cfg.CheckInterval != 12*time.Hour {
		t.Errorf("check interval = %v", cfg.CheckInterval)
	}
	if cfg.StateDir != "/data" {
		t.Errorf("state dir = %q", cfg.StateDir)
	}
}

func TestMultiCAAndAliases(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "gts, letsencrypt")
	t.Setenv("ACME_DEFAULT_EMAIL", "ops@example.com")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CAOrder) != 2 {
		t.Fatalf("CAOrder = %v", cfg.CAOrder)
	}
	gts := cfg.CAs["gts"]
	if !strings.Contains(gts.URL, "pki.goog") {
		t.Errorf("gts url = %q", gts.URL)
	}
	if gts.Email != "ops@example.com" {
		t.Errorf("gts email = %q", gts.Email)
	}
}

func TestStagingRewritesKnownCAs(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "letsencrypt,googletrust")
	t.Setenv("ACME_STAGING", "true")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range cfg.CAOrder {
		if cfg.CAs[name].Environment != EnvStaging {
			t.Errorf("CA %s env = %s, want staging", name, cfg.CAs[name].Environment)
		}
	}
}

// ACME_STAGING maps known production codes but does not filter the configured
// CA set: a CA without a staging counterpart is used as configured.
func TestStagingKeepsNonStagingCAs(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "zerossl")
	t.Setenv("ACME_STAGING", "true")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAs["zerossl"].Environment != EnvProduction {
		t.Fatalf("zerossl env = %s, want production (used as configured)", cfg.CAs["zerossl"].Environment)
	}
}

// ACME_STAGING does not reject an explicitly configured production URL; only
// --dry-run insists on staging/custom endpoints.
func TestStagingAllowsExplicitProductionURL(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "myle")
	t.Setenv("ACME_MYLE_URL", "https://acme-v02.api.letsencrypt.org/directory")
	t.Setenv("ACME_STAGING", "true")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAs["myle"].URL != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("url = %q", cfg.CAs["myle"].URL)
	}
}

func TestDryRunRejectsProductionEndpoint(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "myle")
	t.Setenv("ACME_MYLE_URL", "https://acme-v02.api.letsencrypt.org/directory")
	if _, _, err := Load(true); err == nil {
		t.Fatal("expected --dry-run to refuse a production endpoint")
	}
}

func TestDryRunRejectsProductionCode(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "zerossl")
	if _, _, err := Load(true); err == nil {
		t.Fatal("expected --dry-run to refuse a production CA code")
	}
}

func TestCustomCAURLAllowed(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "pebble")
	t.Setenv("ACME_PEBBLE_URL", "https://localhost:14000/dir")
	t.Setenv("ACME_PEBBLE_EAB_KID", "kid")
	t.Setenv("ACME_PEBBLE_EAB_HMAC", "hmac")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	ca := cfg.CAs["pebble"]
	if ca.URL != "https://localhost:14000/dir" {
		t.Errorf("url = %q", ca.URL)
	}
	if ca.Environment != EnvCustom {
		t.Errorf("env = %q", ca.Environment)
	}
	if ca.EABKid != "kid" || ca.EABHMAC != "hmac" {
		t.Errorf("eab = %q/%q", ca.EABKid, ca.EABHMAC)
	}
}

func TestSecretFileConvention(t *testing.T) {
	clearACMEEnv(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "hmac")
	if err := os.WriteFile(secret, []byte("supersecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "letsencrypt")
	t.Setenv("ACME_LETSENCRYPT_EAB_HMAC_FILE", secret)
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAs["letsencrypt"].EABHMAC != "supersecret" {
		t.Errorf("hmac = %q", cfg.CAs["letsencrypt"].EABHMAC)
	}
}

func TestMissingDNSProviderFails(t *testing.T) {
	clearACMEEnv(t)
	if _, _, err := Load(false); err == nil {
		t.Fatal("expected error without ACME_DNS_PROVIDER")
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	clearACMEEnv(t)
	t.Setenv("ACME_DNS_PROVIDER", "exec")
	t.Setenv("ACME_CA_ORDER", "letsencrypt")
	t.Setenv("ACME_LETSENCRYPT_EAB_KID", "kid-1")
	t.Setenv("ACME_LETSENCRYPT_EAB_HMAC", "topsecret")
	cfg, _, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.Redacted()
	if strings.Contains(out, "topsecret") {
		t.Fatal("redacted output leaked the EAB HMAC")
	}
	if !strings.Contains(out, "PRODUCTION") {
		t.Error("redacted output should mark production CAs")
	}
}
