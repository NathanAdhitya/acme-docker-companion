package acmex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"

	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

// Pebble integration tests exercise the real lego DNS-01 path against a local
// Pebble ACME server and pebble-challtestsrv. They are the staging-equivalent
// tests: they never contact a production ACME endpoint.
//
// Enable with: ACMED_INTEGRATION=1 go test ./internal/acmex/ -v

type pebbleEnv struct {
	caURL  string
	minica string
}

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ACMED_INTEGRATION") != "1" {
		t.Skip("set ACMED_INTEGRATION=1 to run the Pebble integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required")
	}
}

func startPebble(t *testing.T) *pebbleEnv {
	t.Helper()
	suffix := strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())
	netName := "acmed-itest-" + suffix
	challName := "acmed-chall-" + suffix
	pebbleName := "acmed-pebble-" + suffix

	mustDocker(t, "network", "create", netName)
	t.Cleanup(func() { _ = docker("network", "rm", netName) })

	// challtestsrv: DNS on 8053, management on 8055, both published to the host
	// so the in-process lego client can reach them.
	mustDocker(t, "run", "-d", "--name", challName,
		"--network", netName, "--network-alias", "challtestsrv",
		"-p", "127.0.0.1:8055:8055",
		"-p", "127.0.0.1:8053:8053",
		"-p", "127.0.0.1:8053:8053/udp",
		"ghcr.io/letsencrypt/pebble-challtestsrv:latest",
		"-dnsserver", ":8053", "-management", ":8055", "-defaultIPv4", "127.0.0.1")
	t.Cleanup(func() { _ = docker("rm", "-f", challName) })

	// Pebble: ACME on 14000, resolving DNS challenges through challtestsrv.
	mustDocker(t, "run", "-d", "--name", pebbleName,
		"--network", netName,
		"-p", "127.0.0.1:14000:14000",
		"-e", "PEBBLE_VA_NOSLEEP=1",
		"ghcr.io/letsencrypt/pebble:latest",
		"-config", "/test/config/pebble-config.json",
		"-dnsserver", "challtestsrv:8053")
	t.Cleanup(func() { _ = docker("rm", "-f", pebbleName) })

	minica := filepath.Join(t.TempDir(), "pebble.minica.pem")
	cpOut, err := exec.Command("docker", "cp", pebbleName+":/test/certs/pebble.minica.pem", minica).CombinedOutput()
	if err != nil {
		t.Fatalf("docker cp minica: %v\n%s", err, cpOut)
	}

	waitForPebble(t)
	return &pebbleEnv{caURL: "https://localhost:14000/dir", minica: minica}
}

func setupExecProvider(t *testing.T) {
	t.Helper()
	script, err := filepath.Abs("../../test/pebble/update-dns.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXEC_PATH", script)
	t.Setenv("EXEC_SEQUENCE_INTERVAL", "5")
}

func pebbleConfig(t *testing.T, env *pebbleEnv, cas map[string]config.CAConfig, order []string) *config.Config {
	t.Helper()
	return &config.Config{
		CAOrder:                      order,
		CAs:                          cas,
		KeyType:                      certcrypto.EC256,
		DNSProvider:                  "exec",
		DNSResolvers:                 []string{"127.0.0.1:8053"},
		DNSDisableAuthoritativeCheck: true,
		DNSPropagationWait:           time.Second,
		CACert:                       env.minica,
		StateDir:                     t.TempDir(),
		CheckInterval:                12 * time.Hour,
		FailureBackoff:               config.DefaultBackoff,
		MaxConcurrentIssuance:        1,
		FileUID:                      -1,
		FileGID:                      -1,
		FileMode:                     0o644,
		KeyMode:                      0o600,
		LabelPrefix:                  "acmed",
	}
}

func TestPebbleIssueAndRenew(t *testing.T) {
	requireIntegration(t)
	env := startPebble(t)
	setupExecProvider(t)

	cfg := pebbleConfig(t, env, map[string]config.CAConfig{
		"pebble": {Name: "pebble", URL: env.caURL, Environment: config.EnvCustom, Email: "acmed-test@example.com"},
	}, []string{"pebble"})

	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mgr, err := NewManager(cfg, st, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	domains := []string{"acmed-test.example.com", "www.acmed-test.example.com"}
	issued, err := mgr.Issue(context.Background(), IssueRequest{
		Domains:    domains,
		KeyType:    certcrypto.EC256,
		Candidates: []string{"pebble"},
	})
	if err != nil {
		t.Fatalf("issue against Pebble: %v", err)
	}
	if issued.IssuerCA != "pebble" {
		t.Errorf("issuer = %q", issued.IssuerCA)
	}
	if issued.NotAfter.Before(time.Now()) {
		t.Error("issued certificate is already expired")
	}
	certs, err := certcrypto.ParsePEMBundle(issued.FullchainPEM)
	if err != nil || len(certs) == 0 {
		t.Fatalf("parse issued bundle: %v", err)
	}
	gotNames := map[string]bool{}
	for _, n := range certs[0].DNSNames {
		gotNames[n] = true
	}
	for _, d := range domains {
		if !gotNames[d] {
			t.Errorf("issued certificate is missing SAN %q (has %v)", d, certs[0].DNSNames)
		}
	}
	if len(issued.KeyPEM) == 0 {
		t.Error("no private key returned")
	}
	if _, ok, err := st.LoadAccount("pebble"); err != nil || !ok {
		t.Errorf("account not persisted: ok=%v err=%v", ok, err)
	}

	// Renewal reuses the private key and takes the ARI/replaces path.
	issued2, err := mgr.Issue(context.Background(), IssueRequest{
		Domains:    domains,
		KeyType:    certcrypto.EC256,
		Candidates: []string{"pebble"},
		Prev: &PrevCert{
			Domains:   domains,
			KeyType:   certcrypto.EC256,
			IssuerCA:  "pebble",
			IssuerURL: env.caURL,
			CertPEM:   issued.FullchainPEM,
			KeyPEM:    issued.KeyPEM,
		},
	})
	if err != nil {
		t.Fatalf("renew against Pebble: %v", err)
	}
	if string(issued2.KeyPEM) != string(issued.KeyPEM) {
		t.Error("renewal should reuse the private key")
	}
}

func TestPebbleFailover(t *testing.T) {
	requireIntegration(t)
	env := startPebble(t)
	setupExecProvider(t)

	// The first candidate is unreachable; the second is Pebble. Issuance must
	// fail over in order and succeed on Pebble.
	cfg := pebbleConfig(t, env, map[string]config.CAConfig{
		"broken": {Name: "broken", URL: "https://127.0.0.1:1/dir", Environment: config.EnvCustom, Email: "x@example.com"},
		"pebble": {Name: "pebble", URL: env.caURL, Environment: config.EnvCustom, Email: "acmed-test@example.com"},
	}, []string{"broken", "pebble"})

	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mgr, err := NewManager(cfg, st, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	issued, err := mgr.Issue(context.Background(), IssueRequest{
		Domains:    []string{"failover-test.example.com"},
		KeyType:    certcrypto.EC256,
		Candidates: []string{"broken", "pebble"},
	})
	if err != nil {
		t.Fatalf("failover issue: %v", err)
	}
	if issued.IssuerCA != "pebble" {
		t.Fatalf("issuer = %q, want pebble", issued.IssuerCA)
	}
}

// TestPebbleConcurrentIssuance exercises the shared per-CA client: two
// certificates issued at the same time must register a single account and must
// not race on the cached client.
func TestPebbleConcurrentIssuance(t *testing.T) {
	requireIntegration(t)
	env := startPebble(t)
	setupExecProvider(t)

	cfg := pebbleConfig(t, env, map[string]config.CAConfig{
		"pebble": {Name: "pebble", URL: env.caURL, Environment: config.EnvCustom, Email: "acmed-test@example.com"},
	}, []string{"pebble"})

	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mgr, err := NewManager(cfg, st, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	domains := [][]string{
		{"one.concurrent.example.com"},
		{"two.concurrent.example.com"},
	}
	var wg sync.WaitGroup
	issued := make([]*Issued, len(domains))
	errs := make([]error, len(domains))
	for i := range domains {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			issued[i], errs[i] = mgr.Issue(context.Background(), IssueRequest{
				Domains:    domains[i],
				KeyType:    certcrypto.EC256,
				Candidates: []string{"pebble"},
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent issuance %d: %v", i, err)
		}
		if issued[i] == nil || len(issued[i].FullchainPEM) == 0 {
			t.Fatalf("concurrent issuance %d returned no certificate", i)
		}
	}
	acct, ok, err := st.LoadAccount("pebble")
	if err != nil || !ok || len(acct.Registration) == 0 {
		t.Fatalf("account not persisted: ok=%v err=%v", ok, err)
	}
}

// TestPebbleHTTPReqProvider exercises acmed's construction of lego's generic
// httpreq DNS provider against Pebble. An in-process bridge implements the same
// contract acmeproxy.pl exposes (default mode: POST /present and /cleanup with
// {"fqdn","value"}), writing the TXT record into pebble-challtestsrv. This
// covers the acmeproxy.pl-style deployment path end to end.
func TestPebbleHTTPReqProvider(t *testing.T) {
	requireIntegration(t)
	env := startPebble(t)

	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "bob" || pass != "dobbs" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var msg struct {
			FQDN  string `json:"fqdn"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// lego's httpreq default mode must send fqdn/value; RAW mode would send
		// domain/token/keyAuth and would not match acmeproxy.pl.
		if msg.FQDN == "" {
			http.Error(w, "missing fqdn (wrong HTTPREQ_MODE?)", http.StatusBadRequest)
			return
		}

		endpoint, body := "http://localhost:8055/set-txt", map[string]string{"host": msg.FQDN, "value": msg.Value}
		if r.URL.Path == "/cleanup" {
			endpoint, body = "http://localhost:8055/clear-txt", map[string]string{"host": msg.FQDN}
		}
		payload, _ := json.Marshal(body)
		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(payload))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode/100 != 2 {
			http.Error(w, "challtestsrv error", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(bridge.Close)

	t.Setenv("HTTPREQ_ENDPOINT", bridge.URL)
	t.Setenv("HTTPREQ_USERNAME", "bob")
	t.Setenv("HTTPREQ_PASSWORD", "dobbs")
	t.Setenv("HTTPREQ_MODE", "")

	cfg := pebbleConfig(t, env, map[string]config.CAConfig{
		"pebble": {Name: "pebble", URL: env.caURL, Environment: config.EnvCustom, Email: "acmed-test@example.com"},
	}, []string{"pebble"})
	cfg.DNSProvider = "httpreq"

	st, err := store.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mgr, err := NewManager(cfg, st, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	issued, err := mgr.Issue(context.Background(), IssueRequest{
		Domains:    []string{"httpreq-test.example.com"},
		KeyType:    certcrypto.EC256,
		Candidates: []string{"pebble"},
	})
	if err != nil {
		t.Fatalf("issue via httpreq: %v", err)
	}
	certs, err := certcrypto.ParsePEMBundle(issued.FullchainPEM)
	if err != nil || len(certs) == 0 {
		t.Fatalf("parse issued bundle: %v", err)
	}
	if !containsString(certs[0].DNSNames, "httpreq-test.example.com") {
		t.Fatalf("issued certificate lacks the requested SAN: %v", certs[0].DNSNames)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func waitForPebble(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"https://localhost:14000/dir").Output()
		if err == nil && strings.TrimSpace(string(out)) == "200" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("Pebble did not become ready")
}

func mustDocker(t *testing.T, args ...string) {
	t.Helper()
	if out, err := dockerOut(args...); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func docker(args ...string) error {
	_, err := dockerOut(args...)
	return err
}

func dockerOut(args ...string) ([]byte, error) {
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	return cmd.CombinedOutput()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
