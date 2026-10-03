package acmex

import (
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

	res := &certificate.Resource{
		Certificate: leafPEM,
		PrivateKey:  []byte("KEY"),
		CertURL:     "https://ca/cert/1",
	}
	issued, err := toIssued("pebble", "https://ca/dir", res)
	if err != nil {
		t.Fatal(err)
	}
	if issued.IssuerCA != "pebble" || issued.IssuerURL != "https://ca/dir" {
		t.Errorf("issuer = %q %q", issued.IssuerCA, issued.IssuerURL)
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
