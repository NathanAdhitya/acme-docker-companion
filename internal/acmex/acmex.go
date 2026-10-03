// Package acmex wraps the lego ACME client: per-CA accounts (including EAB),
// DNS-01 only, ordered active/backup failover with per-CA cooldowns, and ARI.
package acmex

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	legolib "github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/registration"

	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

// IssueRequest asks for a certificate.
type IssueRequest struct {
	Domains        []string
	KeyType        certcrypto.KeyType
	Profile        string
	PreferredChain string
	// Candidates is the ordered CA list (already resolved against config).
	Candidates []string
	// Prev, when non-nil, carries the previously issued material. The manager
	// renews in place (key reuse + ARI replaces) only on the CA that issued it.
	Prev *PrevCert
}

// PrevCert is the previously issued material for a certificate.
type PrevCert struct {
	IssuerCA  string
	IssuerURL string
	CertPEM   []byte
	KeyPEM    []byte
}

// Issued is the result of a successful issuance or renewal.
type Issued struct {
	IssuerCA     string
	IssuerURL    string
	FullchainPEM []byte
	KeyPEM       []byte
	LeafPEM      []byte
	ChainPEM     []byte
	NotBefore    time.Time
	NotAfter     time.Time
	CertURL      string
}

// ErrCoolingDown reports that every candidate CA is in a cooldown window, so no
// order was attempted. Callers must not count it as a certificate failure.
var ErrCoolingDown = errors.New("all candidate CAs are cooling down")

// ARIWindow is an ACME Renewal Information suggested window. It is an alias
// for lego's type, so the RFC 9773 ShouldRenewAt algorithm stays lego's and
// the manager never re-wraps it.
type ARIWindow = certificate.RenewalInfo

// Issuer is the certificate issuance interface used by the reconciler.
type Issuer interface {
	Issue(ctx context.Context, req IssueRequest) (*Issued, error)
	// RenewalInfo returns the ARI window, or nil when the CA has no ARI.
	RenewalInfo(ctx context.Context, caName string, leaf *x509.Certificate) (*ARIWindow, error)
}

// Manager implements Issuer over a set of lego clients, one per CA.
type Manager struct {
	cfg        *config.Config
	store      *store.Store
	log        *slog.Logger
	httpClient *http.Client
	provider   challenge.Provider
	dnsOptions []dns01.ChallengeOption

	mu       sync.Mutex // guards cooldown
	clientMu sync.Mutex // guards clients; held across the one-time build
	clients  map[string]*caClient
	cooldown map[string]cooldownEntry
}

type cooldownEntry struct {
	until time.Time
	next  time.Duration
	err   string
}

type user struct {
	email string
	key   crypto.Signer
	reg   *acme.ExtendedAccount
}

func (u *user) GetEmail() string                       { return u.email }
func (u *user) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *user) GetPrivateKey() crypto.Signer           { return u.key }

// caClient is one CA's lego client and account.
type caClient struct {
	name   string
	url    string
	client *legolib.Client
}

// NewManager constructs the ACME manager.
func NewManager(cfg *config.Config, st *store.Store, log *slog.Logger) (*Manager, error) {
	if cfg.DNSProvider == "" {
		return nil, errors.New("DNS provider is not configured")
	}
	// Build the provider once; a typo fails fast at startup and each CA client
	// reuses the same instance.
	provider, err := dns.NewDNSChallengeProviderByName(cfg.DNSProvider)
	if err != nil {
		return nil, fmt.Errorf("DNS provider %q: %w", cfg.DNSProvider, err)
	}

	// Configure recursive resolvers for propagation checks. Docker's embedded
	// DNS (127.0.0.11) is a known source of flaky checks, so an explicit list
	// is recommended.
	if len(cfg.DNSResolvers) > 0 {
		opts := dns01.NewOptions()
		opts.RecursiveNameservers = cfg.DNSResolvers
		dns01.SetDefaultClient(dns01.NewClient(opts))
	}

	hc, err := buildHTTPClient(cfg.CACert, cfg.CAServerName)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		cfg:        cfg,
		store:      st,
		log:        log,
		httpClient: hc,
		provider:   provider,
		clients:    map[string]*caClient{},
		cooldown:   map[string]cooldownEntry{},
	}
	if cfg.DNSDisableAuthoritativeCheck {
		m.dnsOptions = append(m.dnsOptions, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	if cfg.DNSPropagationWait > 0 {
		m.dnsOptions = append(m.dnsOptions, dns01.PropagationWait(cfg.DNSPropagationWait, false))
	}
	return m, nil
}

// Issue walks the candidate CAs in order and returns the first success.
func (m *Manager) Issue(ctx context.Context, req IssueRequest) (*Issued, error) {
	candidates := req.Candidates
	if len(candidates) == 0 {
		return nil, errors.New("no candidate CAs configured")
	}

	var failures []string
	attempted := false
	for _, name := range candidates {
		if entry, ok := m.inCooldown(name); ok {
			failures = append(failures, fmt.Sprintf("%s: cooling down until %s (%s)", name, entry.until.Format(time.RFC3339), entry.err))
			continue
		}

		attempted = true
		cli, err := m.client(ctx, name)
		if err != nil {
			// Configuration/account problem: skip without poisoning the CA.
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}

		res, err := m.issueWith(ctx, cli, req)
		if err != nil {
			if isCASide(err) {
				m.setCooldown(name, err)
			}
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		m.clearCooldown(name)
		return toIssued(name, cli.url, res)
	}

	if !attempted {
		// Every candidate was skipped locally. This is not a certificate
		// failure: the caller retries once a cooldown lapses.
		return nil, fmt.Errorf("%w: %s", ErrCoolingDown, strings.Join(failures, "; "))
	}
	return nil, fmt.Errorf("all candidate CAs failed: %s", strings.Join(failures, "; "))
}

// RenewalInfo queries ARI for the certificate at the given CA. A nil window
// means the CA does not implement ARI.
func (m *Manager) RenewalInfo(ctx context.Context, caName string, leaf *x509.Certificate) (*ARIWindow, error) {
	if caName == "" {
		return nil, nil
	}
	cli, err := m.client(ctx, caName)
	if err != nil {
		return nil, err
	}
	ri, err := cli.client.Certificate.GetRenewalInfo(ctx, leaf)
	if errors.Is(err, api.ErrNoARI) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ARI at %s: %w", caName, err)
	}
	return ri, nil
}

func (m *Manager) issueWith(ctx context.Context, cli *caClient, req IssueRequest) (*certificate.Resource, error) {
	// Renew on the issuing CA so the private key is reused and the RFC 9773
	// "replaces" field is sent. Any other CA gets a fresh order. Both the CA
	// name and directory URL must match: the same name maps to different URLs
	// in staging and production.
	if canRenew(req.Prev, cli.name, cli.url) {
		resource := certificate.Resource{
			Domains:     req.Domains,
			KeyType:     req.KeyType,
			PrivateKey:  req.Prev.KeyPEM,
			Certificate: req.Prev.CertPEM,
		}
		return cli.client.Certificate.Renew(ctx, resource, &certificate.RenewOptions{
			KeyType:        req.KeyType,
			Bundle:         true,
			PreferredChain: req.PreferredChain,
			Profile:        req.Profile,
			UseARICertID:   true,
		})
	}
	return cli.client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains:        req.Domains,
		KeyType:        req.KeyType,
		Bundle:         true,
		PreferredChain: req.PreferredChain,
		Profile:        req.Profile,
	})
}

// canRenew reports whether the previous certificate was issued by exactly the
// CA endpoint being tried (name and directory URL), which is the only case in
// which an in-place renewal is valid. A staging certificate must never be
// renewed against production.
func canRenew(prev *PrevCert, caName, caURL string) bool {
	return prev != nil && prev.IssuerCA == caName && prev.IssuerURL == caURL
}

func toIssued(caName, caURL string, res *certificate.Resource) (*Issued, error) {
	certs, err := certcrypto.ParsePEMBundle(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse issued bundle: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("issued bundle contained no certificates")
	}
	leaf := certs[0]
	var chain []byte
	for _, c := range certs[1:] {
		chain = append(chain, certcrypto.PEMEncode(certcrypto.DERCertificateBytes(c.Raw))...)
	}
	return &Issued{
		IssuerCA:     caName,
		IssuerURL:    caURL,
		FullchainPEM: res.Certificate,
		KeyPEM:       res.PrivateKey,
		LeafPEM:      certcrypto.PEMEncode(certcrypto.DERCertificateBytes(leaf.Raw)),
		ChainPEM:     chain,
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		CertURL:      res.CertURL,
	}, nil
}

// --- client construction ---

// client returns the cached client for a CA, building (and registering) it on
// first use. Building registers an account, a one-time operation, so the lock
// is held across it: concurrent issuances then share one account and one
// client. Issuance itself runs outside the lock.
func (m *Manager) client(ctx context.Context, name string) (*caClient, error) {
	ca, ok := m.cfg.CAs[name]
	if !ok {
		return nil, fmt.Errorf("CA %q is not configured", name)
	}

	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if c := m.clients[name]; c != nil {
		return c, nil
	}
	c, err := m.buildClient(ctx, ca)
	if err != nil {
		return nil, err
	}
	m.clients[name] = c
	return c, nil
}

func (m *Manager) buildClient(ctx context.Context, ca config.CAConfig) (*caClient, error) {
	u, err := m.loadUser(ca)
	if err != nil {
		return nil, err
	}

	cfg := legolib.NewConfig(u)
	cfg.CADirURL = ca.URL
	cfg.UserAgent = config.UserAgent
	if m.httpClient != nil {
		cfg.HTTPClient = m.httpClient
	}
	cli, err := legolib.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ACME client for %s: %w", ca.Name, err)
	}
	if err := cli.Challenge.SetDNS01Provider(m.provider, m.dnsOptions...); err != nil {
		return nil, fmt.Errorf("set DNS-01 provider: %w", err)
	}

	// Registering through this client also sets its account URL, so the same
	// client can immediately issue.
	if u.reg == nil {
		if err := m.register(ctx, ca, u, cli); err != nil {
			return nil, err
		}
	}
	return &caClient{name: ca.Name, url: ca.URL, client: cli}, nil
}

// loadUser loads the account key and, when it belongs to this CA endpoint, the
// stored registration.
func (m *Manager) loadUser(ca config.CAConfig) (*user, error) {
	acct, found, err := m.store.LoadAccount(ca.Name)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var reg *acme.ExtendedAccount
	if found {
		signer, err = certcrypto.ParsePEMPrivateKey(acct.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse stored account key for %s: %w", ca.Name, err)
		}
		// A registration is only valid for the directory URL it was created
		// against. Re-register (reusing the key) when the URL changed, e.g.
		// switching between staging and production.
		if len(acct.Registration) > 0 && acct.DirectoryURL == ca.URL {
			var a acme.ExtendedAccount
			if err := json.Unmarshal(acct.Registration, &a); err == nil {
				reg = &a
			}
		}
	} else if ca.AccountKeyFile != "" {
		raw, rerr := os.ReadFile(ca.AccountKeyFile)
		if rerr != nil {
			return nil, fmt.Errorf("read ACME account key file for %s: %w", ca.Name, rerr)
		}
		signer, err = certcrypto.ParsePEMPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key file for %s: %w", ca.Name, err)
		}
	}
	if signer == nil {
		signer, err = certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("generate account key for %s: %w", ca.Name, err)
		}
	}
	return &user{email: ca.Email, key: signer, reg: reg}, nil
}

func (m *Manager) register(ctx context.Context, ca config.CAConfig, u *user, cli *legolib.Client) error {
	var account *acme.ExtendedAccount
	var err error
	switch {
	case ca.EABKid != "" && ca.EABHMAC != "":
		account, err = cli.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  ca.EABKid,
			HmacEncoded:          ca.EABHMAC,
		})
	case ca.Name == "zerossl" && ca.Email != "":
		account, err = registration.RegisterWithZeroSSL(ctx, cli.Registration, ca.Email)
	default:
		account, err = cli.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("register account with %s: %w", ca.Name, err)
	}

	u.reg = account
	regJSON, merr := json.Marshal(account)
	if merr != nil {
		return fmt.Errorf("encode account for %s: %w", ca.Name, merr)
	}
	if err := m.store.SaveAccount(ca.Name, ca.URL, certcrypto.PEMEncode(u.key), regJSON); err != nil {
		return err
	}
	m.log.Info("registered ACME account", "ca", ca.Name, "email", ca.Email)
	return nil
}

// --- cooldowns ---

func (m *Manager) inCooldown(name string) (cooldownEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cooldown[name]
	if !ok || time.Now().UTC().After(entry.until) {
		return cooldownEntry{}, false
	}
	return entry, true
}

func (m *Manager) setCooldown(name string, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.cooldown[name]
	if entry.next == 0 {
		entry.next = 15 * time.Minute
	} else {
		entry.next = min(entry.next*2, 6*time.Hour)
	}
	entry.until = time.Now().UTC().Add(entry.next)
	entry.err = cause.Error()
	m.cooldown[name] = entry
}

func (m *Manager) clearCooldown(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cooldown, name)
}

// --- error classification ---

// isCASide reports whether an error is the CA's fault (so the CA should be
// cooled down) rather than this certificate's (validation, config).
func isCASide(err error) bool {
	if err == nil {
		return false
	}
	var pd *acme.ProblemDetails
	if errors.As(err, &pd) {
		if pd.HTTPStatus >= 500 || pd.HTTPStatus == http.StatusTooManyRequests {
			return true
		}
		switch pd.Type {
		case "urn:ietf:params:acme:error:rateLimited",
			"urn:ietf:params:acme:error:serverInternal",
			"urn:ietf:params:acme:error:badNonce",
			"urn:ietf:params:acme:error:connection":
			return true
		}
		// unauthorized, badCSR, rejectedIdentifier, CAA, etc. are per-cert.
		return false
	}
	// net.Error covers DNS, dial, TLS and url.Error wrapping them.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// --- HTTP client ---

func buildHTTPClient(caCert, serverName string) (*http.Client, error) {
	if caCert == "" && serverName == "" {
		return nil, nil // lego's default client
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, p := range filepath.SplitList(caCert) {
		if p == "" {
			continue
		}
		pemBytes, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil, fmt.Errorf("read ACME_CA_CERT %s: %w", p, rerr)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ACME_CA_CERT %s contains no usable certificates", p)
		}
	}
	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: pool, ServerName: serverName},
		},
	}, nil
}
