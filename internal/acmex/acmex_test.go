package acmex

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"

	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
)

func TestIsCASide(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"server internal", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:serverInternal", HTTPStatus: 500}, true},
		{"rate limited by status", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 429}, true},
		{"rate limited by type", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 400}, true},
		{"bad nonce", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:badNonce", HTTPStatus: 400}, true},
		{"unauthorized is per cert", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", HTTPStatus: 403}, false},
		{"caa is per cert", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:caa", HTTPStatus: 403}, false},
		{"bad CSR is per cert", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:badCSR", HTTPStatus: 400}, false},
		{"network error", &net.DNSError{IsTimeout: true}, true},
		{"wrapped network error", wrappedNetErr{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCASide(tc.err); got != tc.want {
				t.Errorf("isCASide(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type wrappedNetErr struct{}

func (wrappedNetErr) Error() string   { return "network" }
func (wrappedNetErr) Timeout() bool   { return false }
func (wrappedNetErr) Temporary() bool { return false }

var _ net.Error = wrappedNetErr{}

func TestIsCASideWrapped(t *testing.T) {
	inner := &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:serverInternal", HTTPStatus: 500}
	if !isCASide(wrap(inner)) {
		t.Error("wrapped serverInternal should be CA-side")
	}
}

func wrap(err error) error { return errors.Join(errors.New("context"), err) }

func TestCanRenew(t *testing.T) {
	prev := &PrevCert{IssuerCA: "letsencrypt", IssuerURL: "https://acme-v02.api.letsencrypt.org/directory"}
	cases := []struct {
		name string
		prev *PrevCert
		ca   string
		url  string
		want bool
	}{
		{"matching endpoint", prev, "letsencrypt", "https://acme-v02.api.letsencrypt.org/directory", true},
		{"same CA name, staging URL", prev, "letsencrypt", "https://acme-staging-v02.api.letsencrypt.org/directory", false},
		{"different CA", prev, "googletrust", "https://acme-v02.api.letsencrypt.org/directory", false},
		{"no previous certificate", nil, "letsencrypt", "https://acme-v02.api.letsencrypt.org/directory", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canRenew(tc.prev, tc.ca, tc.url); got != tc.want {
				t.Errorf("canRenew = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestToIssuedSplitsBundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := certcrypto.PEMEncode(certcrypto.DERCertificateBytes(der))

	issuerTmpl := *tmpl
	issuerTmpl.SerialNumber = big.NewInt(2)
	issuerTmpl.Subject = pkix.Name{CommonName: "issuer.example.com"}
	issuerTmpl.DNSNames = nil
	issuerDER, err := x509.CreateCertificate(crand.Reader, &issuerTmpl, &issuerTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM := certcrypto.PEMEncode(certcrypto.DERCertificateBytes(issuerDER))

	// lego returns Certificate as the bundle and IssuerCertificate as the chain.
	bundle := append(append([]byte(nil), leafPEM...), issuerPEM...)
	res := &certificate.Resource{
		Certificate:       bundle,
		IssuerCertificate: issuerPEM,
		PrivateKey:        []byte("KEY"),
		CertURL:           "https://ca/cert/1",
	}
	issued, err := toIssued("pebble", "https://ca/dir", res)
	if err != nil {
		t.Fatal(err)
	}
	if issued.IssuerCA != "pebble" || issued.IssuerURL != "https://ca/dir" {
		t.Errorf("issuer = %q %q", issued.IssuerCA, issued.IssuerURL)
	}
	if !bytes.Equal(issued.FullchainPEM, bundle) {
		t.Error("FullchainPEM should be lego's Certificate bundle")
	}
	if !bytes.Equal(issued.ChainPEM, issuerPEM) {
		t.Error("ChainPEM should be lego's IssuerCertificate")
	}
	parsed, err := certcrypto.ParsePEMCertificate(issued.LeafPEM)
	if err != nil {
		t.Fatalf("leaf PEM did not parse: %v", err)
	}
	if parsed.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q", parsed.Subject.CommonName)
	}
	if !issued.NotAfter.Equal(parsed.NotAfter.UTC()) {
		t.Errorf("NotAfter = %v, want %v", issued.NotAfter, parsed.NotAfter.UTC())
	}
}

// TestCooldownLadderDoublesAndCaps covers the DESIGN §8 D2 schedule
// 15m -> 6h, reset by a success (clearCooldown).
func TestCooldownLadderDoublesAndCaps(t *testing.T) {
	m := &Manager{cooldown: map[string]cooldownEntry{}}
	want := []time.Duration{
		15 * time.Minute,
		30 * time.Minute,
		60 * time.Minute,
		120 * time.Minute,
		240 * time.Minute,
		6 * time.Hour,
		6 * time.Hour,
	}
	for i, w := range want {
		m.setCooldown("ca", errors.New("boom"))
		if got := m.cooldown["ca"].next; got != w {
			t.Fatalf("attempt %d: next = %v, want %v", i+1, got, w)
		}
	}

	m.clearCooldown("ca")
	m.setCooldown("ca", errors.New("boom"))
	if got := m.cooldown["ca"].next; got != 15*time.Minute {
		t.Fatalf("a cleared cooldown must restart at 15m, got %v", got)
	}
}

// TestIssueAllCoolingDown: when every candidate is cooling down no order is
// attempted, and the caller is told via ErrCoolingDown.
func TestIssueAllCoolingDown(t *testing.T) {
	m := &Manager{
		cfg:      &config.Config{CAs: map[string]config.CAConfig{"ca": {Name: "ca"}}},
		cooldown: map[string]cooldownEntry{"ca": {until: time.Now().Add(time.Hour), err: "down"}},
	}
	_, err := m.Issue(context.Background(), IssueRequest{Candidates: []string{"ca"}})
	if !errors.Is(err, ErrCoolingDown) {
		t.Fatalf("err = %v, want ErrCoolingDown", err)
	}
}

// TestHTTPReqProviderRequiresEndpoint: the httpreq provider (used for
// acmeproxy.pl-style proxies) is constructed at startup, so a missing
// HTTPREQ_ENDPOINT fails fast before any ACME order is placed.
func TestHTTPReqProviderRequiresEndpoint(t *testing.T) {
	t.Setenv("HTTPREQ_ENDPOINT", "")
	t.Setenv("HTTPREQ_ENDPOINT_FILE", "")
	if _, err := NewManager(&config.Config{DNSProvider: "httpreq"}, nil, testLogger()); err == nil {
		t.Fatal("expected NewManager to fail without HTTPREQ_ENDPOINT")
	}
}

// TestHTTPReqProviderBuildsWithEndpoint: a configured endpoint (and optional
// basic-auth credentials) builds successfully; the provider is stateless and
// shared across CA clients.
func TestHTTPReqProviderBuildsWithEndpoint(t *testing.T) {
	t.Setenv("HTTPREQ_ENDPOINT", "https://acmeproxy.example.com:9443")
	t.Setenv("HTTPREQ_MODE", "")
	t.Setenv("HTTPREQ_USERNAME", "bob")
	t.Setenv("HTTPREQ_PASSWORD", "dobbs")
	if _, err := NewManager(&config.Config{DNSProvider: "httpreq"}, nil, testLogger()); err != nil {
		t.Fatalf("NewManager(httpreq): %v", err)
	}
}
