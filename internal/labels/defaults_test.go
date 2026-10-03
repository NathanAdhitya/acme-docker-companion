package labels

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
)

// TestContainerDefaultsInherited: bare reload/CA/key-type labels apply to every
// named certificate even when no default certificate is defined.
func TestContainerDefaultsInherited(t *testing.T) {
	lbls := map[string]string{
		"acmed.reload.cmd":    "nginx -s reload",
		"acmed.ca":            "gts,letsencrypt",
		"acmed.key-type":      "rsa2048",
		"acmed.api.domains":   "api.example.com",
		"acmed.api.path":      "/certs/api.example.com",
		"acmed.admin.domains": "admin.example.com",
		"acmed.admin.path":    "/certs/admin.example.com",
	}
	reqs, warns := Parse("acmed", lbls)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(reqs) != 2 {
		t.Fatalf("want 2 certificates, got %d", len(reqs))
	}
	for _, r := range reqs {
		if r.ReloadCmd != "nginx -s reload" {
			t.Errorf("%s: reload cmd = %q", r.CertName, r.ReloadCmd)
		}
		if !reflect.DeepEqual(r.CAs, []string{"gts", "letsencrypt"}) {
			t.Errorf("%s: CAs = %v", r.CertName, r.CAs)
		}
		if r.KeyType != certcrypto.RSA2048 {
			t.Errorf("%s: key type = %q", r.CertName, r.KeyType)
		}
	}
}

// TestPerCertOverridesDefault: a named certificate's own reload/CA/key-type
// replaces the container default.
func TestPerCertOverridesDefault(t *testing.T) {
	lbls := map[string]string{
		"acmed.reload.cmd":        "nginx -s reload",
		"acmed.ca":                "gts",
		"acmed.key-type":          "rsa2048",
		"acmed.api.domains":       "api.example.com",
		"acmed.api.path":          "/certs/api.example.com",
		"acmed.api.reload.signal": "SIGHUP",
		"acmed.api.ca":            "letsencrypt",
		"acmed.api.key-type":      "ec384",
	}
	reqs, warns := Parse("acmed", lbls)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 certificate, got %d", len(reqs))
	}
	r := reqs[0]
	if r.ReloadCmd != "" || r.ReloadSignal != "SIGHUP" {
		t.Errorf("reload = %q/%q, want signal SIGHUP", r.ReloadCmd, r.ReloadSignal)
	}
	if !reflect.DeepEqual(r.CAs, []string{"letsencrypt"}) {
		t.Errorf("CAs = %v", r.CAs)
	}
	if r.KeyType != certcrypto.EC384 {
		t.Errorf("key type = %q", r.KeyType)
	}
}

// TestDefaultCertificateInheritsDefaults: the default certificate also uses the
// container defaults (which are its own bare labels).
func TestDefaultCertificateInheritsDefaults(t *testing.T) {
	lbls := map[string]string{
		"acmed.domains":     "example.com",
		"acmed.path":        "/certs/example.com",
		"acmed.reload.cmd":  "nginx -s reload",
		"acmed.api.domains": "api.example.com",
		"acmed.api.path":    "/certs/api.example.com",
	}
	reqs, _ := Parse("acmed", lbls)
	if len(reqs) != 2 {
		t.Fatalf("want 2 certificates, got %d", len(reqs))
	}
	for _, r := range reqs {
		if r.ReloadCmd != "nginx -s reload" {
			t.Errorf("%s: reload = %q", DisplayName(r.CertName), r.ReloadCmd)
		}
	}
}

// TestDefaultsWithoutCertificatesWarn: defaults alone are not a certificate.
func TestDefaultsWithoutCertificatesWarn(t *testing.T) {
	reqs, warns := Parse("acmed", map[string]string{"acmed.reload.cmd": "nginx -s reload"})
	if len(reqs) != 0 {
		t.Fatalf("want no certificates, got %d", len(reqs))
	}
	if len(warns) == 0 || !strings.Contains(strings.Join(warns, " "), "no certificates") {
		t.Fatalf("expected a 'no certificates' warning, got %v", warns)
	}
}

// TestContainerDisableOptsOutEverything: acmed.enable=false disables all
// certificates in the container, including named ones.
func TestContainerDisableOptsOutEverything(t *testing.T) {
	lbls := map[string]string{
		"acmed.enable":      "false",
		"acmed.api.domains": "api.example.com",
		"acmed.api.path":    "/certs/api.example.com",
	}
	reqs, _ := Parse("acmed", lbls)
	if len(reqs) != 0 {
		t.Fatalf("container opt-out should yield no certificates, got %d", len(reqs))
	}
}

// TestNamedCertDisableOnlyAffectsItself.
func TestNamedCertDisableOnlyAffectsItself(t *testing.T) {
	lbls := map[string]string{
		"acmed.api.domains": "api.example.com",
		"acmed.api.path":    "/certs/api.example.com",
		"acmed.api.enable":  "false",
		"acmed.web.domains": "web.example.com",
		"acmed.web.path":    "/certs/web.example.com",
	}
	reqs, warns := Parse("acmed", lbls)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(reqs) != 1 || reqs[0].CertName != "web" {
		t.Fatalf("expected only the web certificate, got %+v", reqs)
	}
}
