package store

import (
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
)

func TestSingleInstanceLock(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("second Open should fail while the first holds the lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after Close should succeed: %v", err)
	}
	_ = second.Close()
}

func TestAccountRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, ok, err := s.LoadAccount("letsencrypt"); err != nil || ok {
		t.Fatalf("expected no account, got ok=%v err=%v", ok, err)
	}
	if err := s.SaveAccount("letsencrypt", "https://ca/dir", []byte("KEYPEM"), []byte(`{"accountURL":"x"}`)); err != nil {
		t.Fatal(err)
	}
	acct, ok, err := s.LoadAccount("letsencrypt")
	if err != nil || !ok {
		t.Fatalf("load account: ok=%v err=%v", ok, err)
	}
	if string(acct.KeyPEM) != "KEYPEM" || acct.DirectoryURL != "https://ca/dir" {
		t.Fatalf("round trip mismatch: %q %q", acct.KeyPEM, acct.DirectoryURL)
	}
	if !strings.Contains(string(acct.Registration), `"accountURL"`) {
		t.Fatalf("registration round trip mismatch: %q", acct.Registration)
	}
}

func TestCertRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id := CertID([]string{"example.com", "www.example.com"}, certcrypto.EC256, "")
	c := &Cert{
		ID:        id,
		Fullchain: []byte("FULL"),
		Privkey:   []byte("KEY"),
		CertPEM:   []byte("CERT"),
		Chain:     []byte("CHAIN"),
		Meta: Meta{
			ID:        id,
			Domains:   []string{"example.com", "www.example.com"},
			KeyType:   string(certcrypto.EC256),
			IssuerCA:  "letsencrypt",
			IssuerURL: "https://acme-v02.api.letsencrypt.org/directory",
		},
	}
	if err := s.SaveCert(c, -1, -1, 0o644, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := s.LoadCert(id)
	if err != nil || got == nil {
		t.Fatalf("load cert: %v", err)
	}
	if string(got.Fullchain) != "FULL" || string(got.Privkey) != "KEY" {
		t.Fatalf("pem mismatch: %q %q", got.Fullchain, got.Privkey)
	}
	if got.Meta.IssuerCA != "letsencrypt" {
		t.Fatalf("issuer = %q", got.Meta.IssuerCA)
	}

	list, err := s.ListCerts()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d, err=%v", len(list), err)
	}
}

func TestSaveMetaOnly(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id := CertID([]string{"a.example.com"}, certcrypto.EC256, "")
	if err := s.SaveMeta(id, Meta{ID: id, ConsecutiveFailures: 2, LastError: "boom"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadCert(id)
	if err != nil || got == nil {
		t.Fatalf("load: %v", err)
	}
	if got.Meta.ConsecutiveFailures != 2 || got.Meta.LastError != "boom" {
		t.Fatalf("meta = %+v", got.Meta)
	}
}

func TestCertIDStable(t *testing.T) {
	a := CertID([]string{"a.example.com", "b.example.com"}, certcrypto.EC256, "")
	b := CertID([]string{"b.example.com", "a.example.com"}, certcrypto.EC256, "")
	if a != b {
		t.Errorf("CertID must be order independent: %q vs %q", a, b)
	}
	if CertID([]string{"a.example.com"}, certcrypto.RSA2048, "") == CertID([]string{"a.example.com"}, certcrypto.EC256, "") {
		t.Error("CertID must differ by key type")
	}
	if CertID([]string{"a.example.com"}, certcrypto.EC256, "shortlived") == CertID([]string{"a.example.com"}, certcrypto.EC256, "") {
		t.Error("CertID must differ by profile")
	}
}
