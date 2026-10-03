package reconciler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"

	"github.com/NathanAdhitya/acme-docker-companion/internal/acmex"
	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

// --- fakes ---

type fakeIssuer struct {
	mu     sync.Mutex
	calls  int
	issued *acmex.Issued
	err    error
}

func (f *fakeIssuer) Issue(_ context.Context, _ acmex.IssueRequest) (*acmex.Issued, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	c := *f.issued
	return &c, nil
}

func (f *fakeIssuer) RenewalInfo(context.Context, string, *x509.Certificate) (*acmex.ARIWindow, error) {
	return nil, nil
}

func (f *fakeIssuer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeDocker struct {
	containers []dockerx.Container
	self       dockerx.Container
	selfOK     bool

	mu      sync.Mutex
	execs   []string
	signals []string
	execErr error
}

func (f *fakeDocker) List(context.Context) ([]dockerx.Container, error) {
	return f.containers, nil
}
func (f *fakeDocker) Events(context.Context, time.Time) (<-chan struct{}, <-chan error) {
	return nil, nil
}
func (f *fakeDocker) Exec(_ context.Context, _ string, cmd []string, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, strings.Join(cmd, " "))
	return "", f.execErr
}
func (f *fakeDocker) Kill(_ context.Context, _, signal string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, signal)
	return f.execErr
}
func (f *fakeDocker) Self(context.Context) (dockerx.Container, bool) {
	return f.self, f.selfOK
}
func (f *fakeDocker) Close() error { return nil }

func (f *fakeDocker) execCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.execs)
}

// --- helpers ---

func makeIssued(t *testing.T, domains []string, caURL string) *acmex.Issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              domains,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	leaf, _ := x509.ParseCertificate(der)
	return &acmex.Issued{
		IssuerCA:     "letsencrypt",
		IssuerURL:    caURL,
		FullchainPEM: certPEM,
		KeyPEM:       keyPEM,
		LeafPEM:      certPEM,
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
	}
}

func testConfig(t *testing.T, caURL string) *config.Config {
	t.Helper()
	return &config.Config{
		CAOrder: []string{"letsencrypt"},
		CAs: map[string]config.CAConfig{
			"letsencrypt": {Name: "letsencrypt", URL: caURL, Environment: config.EnvStaging},
		},
		KeyType:               certcrypto.EC256,
		StateDir:              t.TempDir(),
		CheckInterval:         12 * time.Hour,
		FailureBackoff:        config.DefaultBackoff,
		MaxConcurrentIssuance: 2,
		FileUID:               -1,
		FileGID:               -1,
		FileMode:              0o644,
		KeyMode:               0o600,
		LabelPrefix:           "acmed",
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testCAURL is a staging endpoint used only as a fake issuer identity in tests.
const testCAURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// openTestStore opens the state directory and closes it at test cleanup.
func openTestStore(t *testing.T, cfg *config.Config) *store.Store {
	t.Helper()
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// testDocker returns a fake Docker client with one container mounting a fresh
// host directory at /etc/nginx/certs and the manager mounting the same host
// directory at a separate root. Both directories are returned.
func testDocker(t *testing.T, labels map[string]string) (hostSource, managerRoot string, d *fakeDocker) {
	t.Helper()
	hostSource, managerRoot = t.TempDir(), t.TempDir()
	d = &fakeDocker{
		containers: []dockerx.Container{{
			ID: "c1", Name: "web", Labels: labels,
			Mounts: []dockerx.Mount{{Destination: "/etc/nginx/certs", Source: hostSource}},
		}},
		self:   dockerx.Container{ID: "self", Mounts: []dockerx.Mount{{Destination: managerRoot, Source: hostSource}}},
		selfOK: true,
	}
	return hostSource, managerRoot, d
}

// --- tests ---

func TestIssueDeliverAndReload(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.domains":    "example.com",
		"acmed.path":       "/etc/nginx/certs/example.com",
		"acmed.reload.cmd": "nginx -s reload",
	}
	_, managerRoot, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	// Certificate files delivered.
	if _, err := os.Stat(managerRoot + "/example.com/fullchain.pem"); err != nil {
		t.Fatalf("fullchain not delivered: %v", err)
	}
	if _, err := os.Stat(managerRoot + "/example.com/privkey.pem"); err != nil {
		t.Fatalf("privkey not delivered: %v", err)
	}
	if docker.execCount() != 1 {
		t.Fatalf("expected exactly one reload, got %d", docker.execCount())
	}
	if issuer.callCount() != 1 {
		t.Fatalf("expected one issuance, got %d", issuer.callCount())
	}

	snap := rec.Snapshot()
	if len(snap.Certs) != 1 {
		t.Fatalf("certs = %d", len(snap.Certs))
	}
	tg := snap.Certs[0].Targets[0]
	if !tg.Delivered || tg.Reload != "ok" {
		t.Fatalf("target status = %+v", tg)
	}

	// A second cycle must not reissue or reload.
	rec.Once(context.Background())
	if issuer.callCount() != 1 {
		t.Fatalf("cache-first violated: %d issuances", issuer.callCount())
	}
	if docker.execCount() != 1 {
		t.Fatalf("unchanged content should not reload: %d reloads", docker.execCount())
	}
}

// TestCachedCertReusedAcrossCandidateChange: a cached certificate issued by a
// different CA endpoint keeps serving until it is due, and candidate changes
// never force reissuance (the cache protects ACME rate limits).
func TestCachedCertReusedAcrossCandidateChange(t *testing.T) {
	stagingURL := testCAURL
	prodURL := "https://acme-v02.api.letsencrypt.org/directory"

	cfg := testConfig(t, prodURL) // candidates now point at production
	st := openTestStore(t, cfg)

	// Seed the cache with a certificate issued by the staging CA.
	old := makeIssued(t, []string{"example.com"}, stagingURL)
	id := store.CertID([]string{"example.com"}, certcrypto.EC256, "")
	if err := st.SaveCert(&store.Cert{
		ID: id, Fullchain: old.FullchainPEM, Privkey: old.KeyPEM, CertPEM: old.LeafPEM,
		Meta: store.Meta{ID: id, Domains: []string{"example.com"}, KeyType: string(certcrypto.EC256),
			IssuerCA: "letsencrypt", IssuerURL: stagingURL, NotBefore: old.NotBefore, NotAfter: old.NotAfter},
	}, -1, -1, 0o644, 0o600); err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"}
	_, managerRoot, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, prodURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	if issuer.callCount() != 0 {
		t.Fatalf("a cached certificate must be reused until due; issuances=%d", issuer.callCount())
	}
	// A cached certificate from any endpoint is delivered to targets.
	if _, err := os.Stat(managerRoot + "/example.com/fullchain.pem"); err != nil {
		t.Fatalf("cached certificate not delivered: %v", err)
	}
	snap := rec.Snapshot()
	if len(snap.Certs) != 1 || len(snap.Certs[0].Targets) != 1 {
		t.Fatalf("unexpected status: %+v", snap.Certs)
	}
	if !snap.Certs[0].Targets[0].Delivered {
		t.Fatalf("target should report delivered: %+v", snap.Certs[0].Targets[0])
	}
	loaded, err := st.LoadCert(id)
	if err != nil || loaded == nil {
		t.Fatal(err)
	}
	if loaded.Meta.IssuerURL != stagingURL {
		t.Fatalf("cache was rewritten without issuance: %q", loaded.Meta.IssuerURL)
	}
}

// TestCandidatesRefreshOnLabelChange: CA candidates are recomputed each resync
// from the current requests, so a recreated container with a different
// acmed.ca is honoured without restarting the manager.
func TestCandidatesRefreshOnLabelChange(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	cfg.CAOrder = []string{"letsencrypt", "gts"}
	cfg.CAs["gts"] = config.CAConfig{Name: "gts", URL: "https://acme.gts.example/directory", Environment: config.EnvProduction}
	st := openTestStore(t, cfg)

	labels := map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())
	if got := rec.Snapshot().Certs[0].Candidates; !slices.Equal(got, []string{"letsencrypt", "gts"}) {
		t.Fatalf("initial candidates = %v", got)
	}

	// The container is recreated with a CA override (labels are immutable).
	docker.containers[0].Labels["acmed.ca"] = "gts"

	rec.Once(context.Background())
	if got := rec.Snapshot().Certs[0].Candidates; !slices.Equal(got, []string{"gts"}) {
		t.Fatalf("candidates after label change = %v", got)
	}
}

// TestCacheValidRequiresPrivateKey: a cached certificate whose private key is
// missing is not usable, so delivery cannot remove the target's key.
func TestCacheValidRequiresPrivateKey(t *testing.T) {
	cs := &certState{
		leaf: &x509.Certificate{},
		cert: &store.Cert{Fullchain: []byte("fullchain")},
	}
	if cs.cacheValid() {
		t.Fatal("a cache without a private key must not be valid")
	}
	cs.cert.Privkey = []byte("privkey")
	if !cs.cacheValid() {
		t.Fatal("a complete cache should be valid")
	}
}

func TestReloadFailureIsRetried(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.domains":    "example.com",
		"acmed.path":       "/etc/nginx/certs/example.com",
		"acmed.reload.cmd": "nginx -s reload",
	}
	_, _, docker := testDocker(t, labels)
	docker.execErr = errFake("reload failed")
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	if snap := rec.Snapshot(); snap.Certs[0].Targets[0].Reload != "failed" {
		t.Fatalf("expected reload=failed, got %+v", snap.Certs[0].Targets[0])
	}

	docker.mu.Lock()
	docker.execErr = nil
	docker.mu.Unlock()

	rec.Once(context.Background())
	if snap := rec.Snapshot(); snap.Certs[0].Targets[0].Reload != "ok" {
		t.Fatalf("expected reload retry to succeed, got %+v", snap.Certs[0].Targets[0])
	}
}

func TestMisconfiguredTargetDegradesNotCrashes(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	// The target mounts nothing covering the path.
	container := dockerx.Container{
		ID: "c1", Name: "web",
		Labels: map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"},
		Mounts: nil,
	}
	docker := &fakeDocker{
		containers: []dockerx.Container{container},
		self:       dockerx.Container{ID: "self", Mounts: nil},
		selfOK:     true,
	}
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	snap := rec.Snapshot()
	if len(snap.Warnings) == 0 {
		t.Fatal("expected a warning about the unmappable path")
	}
	if snap.Certs[0].Targets[0].Reload != "misconfigured" {
		t.Fatalf("target = %+v", snap.Certs[0].Targets[0])
	}
}

func TestSignalReload(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{
		"acmed.domains":       "example.com",
		"acmed.path":          "/etc/nginx/certs/example.com",
		"acmed.reload.signal": "SIGHUP",
	}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{issued: makeIssued(t, []string{"example.com"}, testCAURL)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	docker.mu.Lock()
	defer docker.mu.Unlock()
	if len(docker.signals) != 1 || docker.signals[0] != "SIGHUP" {
		t.Fatalf("signals = %v", docker.signals)
	}
}

// TestIssuanceBackoffHonored: a failed issuance must not be retried on every
// due tick; the persisted backoff gates it (DESIGN §9).
func TestIssuanceBackoffHonored(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{err: errFake("ca down")}

	clock := time.Now().UTC()
	rec := New(cfg, docker, issuer, st, testLogger())
	rec.now = func() time.Time { return clock }

	ctx := context.Background()
	rec.Once(ctx)
	if issuer.callCount() != 1 {
		t.Fatalf("first cycle should attempt issuance, calls=%d", issuer.callCount())
	}

	// Inside the 1m backoff window a second cycle must not attempt.
	clock = clock.Add(30 * time.Second)
	rec.Once(ctx)
	if issuer.callCount() != 1 {
		t.Fatalf("issuance retried before the backoff elapsed; calls=%d", issuer.callCount())
	}

	// Past the window it may try again.
	clock = clock.Add(time.Minute)
	rec.Once(ctx)
	if issuer.callCount() != 2 {
		t.Fatalf("issuance did not retry after the backoff; calls=%d", issuer.callCount())
	}
}

// blockingIssuer holds an issuance open until released, to prove that
// /healthz (Snapshot) never waits on in-flight ACME work.
type blockingIssuer struct {
	started chan struct{}
	release chan struct{}
	issued  *acmex.Issued
}

func (b *blockingIssuer) Issue(context.Context, acmex.IssueRequest) (*acmex.Issued, error) {
	close(b.started)
	<-b.release
	c := *b.issued
	return &c, nil
}

func (b *blockingIssuer) RenewalInfo(context.Context, string, *x509.Certificate) (*acmex.ARIWindow, error) {
	return nil, nil
}

// TestSnapshotDoesNotBlockOnIssuance: the status endpoint serves the last
// published snapshot, so it stays responsive while a certificate is issuing
// (DESIGN §15 D5).
func TestSnapshotDoesNotBlockOnIssuance(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"}
	_, _, docker := testDocker(t, labels)
	issuer := &blockingIssuer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		issued:  makeIssued(t, []string{"example.com"}, testCAURL),
	}

	rec := New(cfg, docker, issuer, st, testLogger())
	done := make(chan struct{})
	go func() {
		rec.Once(context.Background())
		close(done)
	}()
	<-issuer.started

	snapDone := make(chan Status, 1)
	go func() { snapDone <- rec.Snapshot() }()
	select {
	case <-snapDone:
	case <-time.After(2 * time.Second):
		close(issuer.release)
		<-done
		t.Fatal("Snapshot blocked behind an in-flight issuance")
	}

	close(issuer.release)
	<-done
}

// TestGCRemovesExpiredUnreferenced: expired certificates no running container
// references are removed; unexpired or referenced ones are kept.
func TestGCRemovesExpiredUnreferenced(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	now := time.Now().UTC()
	expiredID := store.CertID([]string{"old.example.com"}, certcrypto.EC256, "")
	liveID := store.CertID([]string{"live.example.com"}, certcrypto.EC256, "")
	for _, c := range []struct {
		id       string
		notAfter time.Time
	}{
		{expiredID, now.Add(-time.Hour)},
		{liveID, now.Add(90 * 24 * time.Hour)},
	} {
		if err := st.SaveCert(&store.Cert{
			ID:   c.id,
			Meta: store.Meta{ID: c.id, NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: c.notAfter},
		}, -1, -1, 0o644, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	rec := New(cfg, &fakeDocker{}, &fakeIssuer{}, st, testLogger())
	rec.Once(context.Background())

	if got, err := st.LoadCert(expiredID); err != nil || got != nil {
		t.Fatalf("expired unreferenced certificate should be gone (err=%v)", err)
	}
	if got, err := st.LoadCert(liveID); err != nil || got == nil {
		t.Fatalf("unexpired certificate must be kept (err=%v)", err)
	}
}

// TestARIRefreshHonorsRetryAfter: the next ARI query waits at least for the
// server's Retry-After when that is longer than the check interval.
func TestARIRefreshHonorsRetryAfter(t *testing.T) {
	cfg := testConfig(t, "https://acme-staging-v02.api.letsencrypt.org/directory")
	rec := New(cfg, nil, nil, nil, testLogger())

	if got := rec.ariRefreshAfter(&certState{cert: &store.Cert{}}); got != cfg.CheckInterval {
		t.Fatalf("refresh interval = %v, want %v", got, cfg.CheckInterval)
	}
	cs := &certState{cert: &store.Cert{Meta: store.Meta{ARIValid: true, ARIRetryAfter: 20 * time.Hour}}}
	if got := rec.ariRefreshAfter(cs); got != 20*time.Hour {
		t.Fatalf("refresh interval = %v, want 20h", got)
	}
	cs.cert.Meta.ARIRetryAfter = time.Minute
	if got := rec.ariRefreshAfter(cs); got != cfg.CheckInterval {
		t.Fatalf("a short Retry-After must not shorten the cadence: %v", got)
	}
}

// TestCoolingDownDoesNotGrowBackoff: a candidate-wide cooldown is not a
// certificate failure, so it must not grow the retry backoff (DESIGN §8 D2/D4).
func TestCoolingDownDoesNotGrowBackoff(t *testing.T) {
	cfg := testConfig(t, testCAURL)
	st := openTestStore(t, cfg)

	labels := map[string]string{"acmed.domains": "example.com", "acmed.path": "/etc/nginx/certs/example.com"}
	_, _, docker := testDocker(t, labels)
	issuer := &fakeIssuer{err: fmt.Errorf("deferred: %w", acmex.ErrCoolingDown)}

	rec := New(cfg, docker, issuer, st, testLogger())
	rec.Once(context.Background())

	id := store.CertID([]string{"example.com"}, certcrypto.EC256, "")
	cert, err := st.LoadCert(id)
	if err != nil || cert == nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if cert.Meta.ConsecutiveFailures != 0 {
		t.Fatalf("a cooldown must not count as a failure: %+v", cert.Meta)
	}
	if !cert.Meta.NextAttempt.IsZero() {
		t.Fatalf("a cooldown must not set a retry backoff: %v", cert.Meta.NextAttempt)
	}
	if cert.Meta.LastError == "" {
		t.Fatal("the deferral should still be recorded in LastError")
	}
}

// --- tiny helpers to avoid extra imports ---

type errFake string

func (e errFake) Error() string { return string(e) }
