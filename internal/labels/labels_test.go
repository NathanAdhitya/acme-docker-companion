package labels

import (
	"reflect"
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
)

func TestParseDefaultCert(t *testing.T) {
	lbls := map[string]string{
		"acmed.domains":      "Example.com, *.example.com",
		"acmed.path":         "/etc/nginx/certs/example.com",
		"acmed.reload.cmd":   "nginx -s reload",
		"acmed.key-type":     "rsa2048",
		"acmed.ca":           "gts, letsencrypt",
		"acmed.manager-path": "/certs/example.com",
		"unrelated":          "ignored",
	}
	reqs, warns := Parse("acmed", lbls)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.CertName != "" {
		t.Errorf("cert name = %q, want default", r.CertName)
	}
	wantDomains := []string{"example.com", "*.example.com"}
	if !reflect.DeepEqual(r.Domains, wantDomains) {
		t.Errorf("domains = %v, want %v", r.Domains, wantDomains)
	}
	if r.Path != "/etc/nginx/certs/example.com" {
		t.Errorf("path = %q", r.Path)
	}
	if r.ReloadCmd != "nginx -s reload" {
		t.Errorf("reload cmd = %q", r.ReloadCmd)
	}
	if r.KeyType != certcrypto.RSA2048 {
		t.Errorf("key type = %q", r.KeyType)
	}
	if !reflect.DeepEqual(r.CAs, []string{"gts", "letsencrypt"}) {
		t.Errorf("CAs = %v", r.CAs)
	}
	if r.ManagerPath != "/certs/example.com" {
		t.Errorf("manager path = %q", r.ManagerPath)
	}
}

func TestParseNamedCerts(t *testing.T) {
	lbls := map[string]string{
		"acmed.domains":           "example.com",
		"acmed.path":              "/certs/example.com",
		"acmed.web.domains":       "api.example.com",
		"acmed.web.path":          "/certs/api.example.com",
		"acmed.web.reload.signal": "SIGHUP",
		"acmed.mail.domains":      "mail.example.com",
		"acmed.mail.path":         "/certs/mail.example.com",
		"acmed.mail.reload.cmd":   "/reload.sh",
	}
	reqs, warns := Parse("acmed", lbls)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(reqs) != 3 {
		t.Fatalf("want 3 requests, got %d: %+v", len(reqs), reqs)
	}
	byName := map[string]Request{}
	for _, r := range reqs {
		byName[r.CertName] = r
	}
	if byName["web"].ReloadSignal != "SIGHUP" {
		t.Errorf("web signal = %q", byName["web"].ReloadSignal)
	}
	if byName["mail"].ReloadCmd != "/reload.sh" {
		t.Errorf("mail cmd = %q", byName["mail"].ReloadCmd)
	}
}

func TestParseValidation(t *testing.T) {
	cases := []struct {
		name    string
		lbls    map[string]string
		wantReq int
	}{
		{
			name:    "missing domains",
			lbls:    map[string]string{"acmed.path": "/certs/x"},
			wantReq: 0,
		},
		{
			name:    "relative path",
			lbls:    map[string]string{"acmed.domains": "a.example.com", "acmed.path": "certs/x"},
			wantReq: 0,
		},
		{
			name: "both reload mechanisms",
			lbls: map[string]string{
				"acmed.domains": "a.example.com", "acmed.path": "/certs/x",
				"acmed.reload.cmd": "x", "acmed.reload.signal": "SIGHUP",
			},
			wantReq: 0,
		},
		{
			name:    "bad signal",
			lbls:    map[string]string{"acmed.domains": "a.example.com", "acmed.path": "/certs/x", "acmed.reload.signal": "SIGNOPE"},
			wantReq: 0,
		},
		{
			name:    "wildcard not leftmost",
			lbls:    map[string]string{"acmed.domains": "foo.*.example.com", "acmed.path": "/certs/x"},
			wantReq: 0,
		},
		{
			name:    "enable false",
			lbls:    map[string]string{"acmed.domains": "a.example.com", "acmed.path": "/certs/x", "acmed.enable": "false"},
			wantReq: 0,
		},
		{
			name: "duplicate path",
			lbls: map[string]string{
				"acmed.domains": "a.example.com", "acmed.path": "/certs/shared",
				"acmed.b.domains": "b.example.com", "acmed.b.path": "/certs/shared",
			},
			wantReq: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs, _ := Parse("acmed", tc.lbls)
			if len(reqs) != tc.wantReq {
				t.Errorf("got %d requests, want %d (%+v)", len(reqs), tc.wantReq, reqs)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"EXAMPLE.com.":  "example.com",
		"*.Example.COM": "*.example.com",
		"bücher.de":     "xn--bcher-kva.de",
	}
	for in, want := range cases {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "localhost", "a.*.b.com", "-bad.com", "a..b.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
