// Package config loads and validates acmed's configuration from the
// environment, supporting the _FILE convention for secrets and an ordered
// active/backup list of ACME certificate authorities.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	legolib "github.com/go-acme/lego/v5/lego"
)

// UserAgent identifies acmed to ACME servers.
const UserAgent = "acmed/acme-docker-companion"

// Environment classifies a CA endpoint for status reporting.
type Environment string

const (
	EnvProduction Environment = "production"
	EnvStaging    Environment = "staging"
	EnvCustom     Environment = "custom"
)

// CAConfig describes one certificate authority in the candidate order.
type CAConfig struct {
	Name           string
	URL            string
	Environment    Environment
	Email          string
	EABKid         string
	EABHMAC        string
	AccountKeyFile string
}

// Config is the fully resolved runtime configuration.
type Config struct {
	// Docker
	DockerHost string

	// ACME
	CAOrder        []string
	CAs            map[string]CAConfig
	DefaultEmail   string
	Staging        bool
	KeyType        certcrypto.KeyType
	PreferredChain string
	Profile        string
	CACert         string
	CAServerName   string

	// DNS-01
	DNSProvider                  string
	DNSResolvers                 []string
	DNSDisableAuthoritativeCheck bool
	DNSPropagationWait           time.Duration

	// Runtime
	StateDir              string
	CheckInterval         time.Duration
	RenewBefore           time.Duration
	FailureBackoff        []time.Duration
	MaxConcurrentIssuance int
	FileUID               int
	FileGID               int
	FileMode              os.FileMode
	KeyMode               os.FileMode
	LabelPrefix           string
	LogLevel              string
	HTTPAddr              string

	// DryRun issues against staging, stores state under a separate directory
	// and never delivers or reloads.
	DryRun bool
}

// DefaultBackoff is the retry schedule recommended by Let's Encrypt.
var DefaultBackoff = []time.Duration{1 * time.Minute, 10 * time.Minute, 100 * time.Minute, 24 * time.Hour}

// caAliases maps friendly names to canonical lego CA codes.
var caAliases = map[string]string{
	"gts":              "googletrust",
	"gts-staging":      "googletrust-staging",
	"google":           "googletrust",
	"google-staging":   "googletrust-staging",
	"le":               "letsencrypt",
	"le-staging":       "letsencrypt-staging",
	"letsencrypt-prod": "letsencrypt",
}

// stagingCounterpart maps production codes to their staging equivalents.
var stagingCounterpart = map[string]string{
	"letsencrypt": "letsencrypt-staging",
	"googletrust": "googletrust-staging",
}

// Load resolves configuration from the environment. It returns the config,
// non-fatal warnings, and an error for anything fatal.
func Load(dryRun bool) (*Config, []string, error) {
	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	cfg := &Config{
		DockerHost:     envDefault("DOCKER_HOST", "unix:///var/run/docker.sock"),
		Staging:        envBool("ACME_STAGING", false),
		DryRun:         dryRun,
		PreferredChain: env("ACME_PREFERRED_CHAIN"),
		Profile:        env("ACME_PROFILE"),
		CACert:         env("ACME_CA_CERT"),
		CAServerName:   env("ACME_CA_SERVER_NAME"),
		DNSProvider:    env("ACME_DNS_PROVIDER"),
		LabelPrefix:    envDefault("LABEL_PREFIX", "acmed"),
		LogLevel:       envDefault("LOG_LEVEL", "info"),
		HTTPAddr:       HTTPAddr(),
		DefaultEmail:   env("ACME_DEFAULT_EMAIL"),
		FileUID:        envInt("FILE_UID", -1),
		FileGID:        envInt("FILE_GID", -1),
		FileMode:       envMode("FILE_MODE", 0o644),
		KeyMode:        envMode("KEY_MODE", 0o640),
	}

	if dryRun {
		cfg.Staging = true
	}

	// Key type
	kt := envDefault("ACME_KEY_TYPE", "EC256")
	parsedKT, err := certcrypto.ToKeyType(kt)
	if err != nil {
		return nil, warnings, fmt.Errorf("ACME_KEY_TYPE %q: %w", kt, err)
	}
	cfg.KeyType = parsedKT

	// Durations
	cfg.CheckInterval, err = envDuration("CHECK_INTERVAL", 12*time.Hour)
	if err != nil {
		return nil, warnings, err
	}
	if cfg.CheckInterval <= 0 {
		return nil, warnings, fmt.Errorf("CHECK_INTERVAL must be positive")
	}
	cfg.RenewBefore, err = envDuration("RENEW_BEFORE", 0)
	if err != nil {
		return nil, warnings, err
	}
	cfg.FailureBackoff, err = envDurationList("FAILURE_BACKOFF", DefaultBackoff)
	if err != nil {
		return nil, warnings, err
	}
	cfg.MaxConcurrentIssuance = max(envInt("MAX_CONCURRENT_ISSUANCE", 2), 1)

	cfg.StateDir = envDefault("STATE_DIR", "/data")
	if dryRun {
		cfg.StateDir = filepath.Join(cfg.StateDir, "dryrun")
	}

	// DNS resolvers
	if raw := env("ACME_DNS_RESOLVERS"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				cfg.DNSResolvers = append(cfg.DNSResolvers, p)
			}
		}
	}
	cfg.DNSDisableAuthoritativeCheck = envBool("ACME_DNS_DISABLE_AUTHORITATIVE_CHECK", false)
	cfg.DNSPropagationWait, err = envDuration("ACME_DNS_PROPAGATION_WAIT", 0)
	if err != nil {
		return nil, warnings, err
	}

	// CA order: de-duplicated, preserving the configured order.
	orderRaw := envDefault("ACME_CA_ORDER", "letsencrypt")
	seen := map[string]bool{}
	for _, name := range strings.Split(orderRaw, ",") {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		if seen[name] {
			warnf("duplicate CA %q in ACME_CA_ORDER; ignoring the repeat", name)
			continue
		}
		seen[name] = true
		cfg.CAOrder = append(cfg.CAOrder, name)
	}
	if len(cfg.CAOrder) == 0 {
		return nil, warnings, fmt.Errorf("ACME_CA_ORDER is empty")
	}

	cfg.CAs = map[string]CAConfig{}
	for _, name := range cfg.CAOrder {
		ca, err := resolveCA(name, cfg)
		if err != nil {
			return nil, warnings, err
		}
		cfg.CAs[name] = ca
	}

	if cfg.DNSProvider == "" {
		return nil, warnings, fmt.Errorf("ACME_DNS_PROVIDER is required (DNS-01 only)")
	}

	return cfg, warnings, nil
}

// resolveCA builds a CAConfig for name. ACME_STAGING rewrites known production
// codes to their staging counterparts; CAs without one are used exactly as
// configured. Only --dry-run insists on staging/custom endpoints.
func resolveCA(name string, cfg *Config) (CAConfig, error) {
	envName := envKey(name)
	explicitURL := env("ACME_" + envName + "_URL")

	code := canonicalCode(name)
	url := ""
	environment := EnvProduction

	if explicitURL != "" {
		if strings.HasPrefix(explicitURL, "https://") || strings.HasPrefix(explicitURL, "http://") {
			url = explicitURL
			environment = classifyURL(explicitURL)
		} else {
			code = canonicalCode(explicitURL)
			u, uerr := legolib.GetDirectoryURL(code)
			if uerr != nil {
				return CAConfig{}, fmt.Errorf("ACME_%s_URL %q is not a URL or known CA code: %w", envName, explicitURL, uerr)
			}
			url = u
			environment = classifyCode(code)
		}
	} else {
		if cfg.Staging {
			if counterpart, ok := stagingCounterpart[code]; ok {
				code = counterpart
			}
		}
		u, uerr := legolib.GetDirectoryURL(code)
		if uerr != nil {
			return CAConfig{}, fmt.Errorf("unknown CA %q (no ACME_%s_URL set and not a built-in code): %w", name, envName, uerr)
		}
		url = u
		environment = classifyCode(code)
	}

	// --dry-run must never reach a production endpoint (DESIGN §16). Plain
	// ACME_STAGING does not restrict the configured CA set.
	if cfg.DryRun && environment == EnvProduction {
		return CAConfig{}, fmt.Errorf("--dry-run requires a staging or custom endpoint; CA %q resolves to %s (set ACME_%s_URL or remove it from ACME_CA_ORDER)", name, url, envName)
	}

	email := env("ACME_" + envName + "_EMAIL")
	if email == "" {
		email = cfg.DefaultEmail
	}

	return CAConfig{
		Name:           name,
		URL:            url,
		Environment:    environment,
		Email:          email,
		EABKid:         env("ACME_" + envName + "_EAB_KID"),
		EABHMAC:        env("ACME_" + envName + "_EAB_HMAC"),
		AccountKeyFile: env("ACME_" + envName + "_ACCOUNT_KEY_FILE"),
	}, nil
}

func canonicalCode(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if alias, ok := caAliases[name]; ok {
		return alias
	}
	return name
}

func classifyCode(code string) Environment {
	if strings.Contains(code, "staging") {
		return EnvStaging
	}
	return EnvProduction
}

func classifyURL(url string) Environment {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "staging"):
		return EnvStaging
	case strings.Contains(lower, "localhost"), strings.Contains(lower, "127.0.0.1"), strings.Contains(lower, "pebble"):
		return EnvCustom
	default:
		return EnvProduction
	}
}

// ResolveCandidates intersects the requested names with configured CAs,
// preserving the configured order. An empty request uses the global order.
// Unknown names are returned as warnings.
func (c *Config) ResolveCandidates(requested []string) (names []string, warnings []string) {
	if len(requested) == 0 {
		return append([]string(nil), c.CAOrder...), nil
	}
	want := map[string]bool{}
	for _, n := range requested {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if _, ok := c.CAs[n]; !ok {
			warnings = append(warnings, fmt.Sprintf("unknown or disabled CA %q (configured: %s)", n, strings.Join(c.CAOrder, ",")))
			continue
		}
		want[n] = true
	}
	for _, n := range c.CAOrder {
		if want[n] {
			names = append(names, n)
		}
	}
	return names, warnings
}

// Redacted returns a printable summary of the effective configuration with
// secrets removed. It is used by `acmed check`.
func (c *Config) Redacted() string {
	var b strings.Builder
	fmt.Fprintf(&b, "label prefix:      %s\n", c.LabelPrefix)
	fmt.Fprintf(&b, "state dir:         %s\n", c.StateDir)
	fmt.Fprintf(&b, "check interval:    %s\n", c.CheckInterval)
	fmt.Fprintf(&b, "key type:          %s\n", c.KeyType)
	if c.Profile != "" {
		fmt.Fprintf(&b, "profile:           %s\n", c.Profile)
	}
	if c.PreferredChain != "" {
		fmt.Fprintf(&b, "preferred chain:   %s\n", c.PreferredChain)
	}
	fmt.Fprintf(&b, "dns provider:      %s\n", c.DNSProvider)
	if len(c.DNSResolvers) > 0 {
		fmt.Fprintf(&b, "dns resolvers:     %s\n", strings.Join(c.DNSResolvers, ","))
	}
	if c.DNSDisableAuthoritativeCheck {
		fmt.Fprintf(&b, "dns auth check:    disabled\n")
	}
	if c.DNSPropagationWait > 0 {
		fmt.Fprintf(&b, "dns propagation:   %s\n", c.DNSPropagationWait)
	}
	fmt.Fprintf(&b, "dry run:           %v\n", c.DryRun)
	fmt.Fprintf(&b, "staging:           %v\n", c.Staging)
	fmt.Fprintf(&b, "max concurrent:    %d\n", c.MaxConcurrentIssuance)
	fmt.Fprintf(&b, "file uid/gid/mode: %d/%d/%#o key=%#o\n", c.FileUID, c.FileGID, c.FileMode, c.KeyMode)
	fmt.Fprintf(&b, "docker host:       %s\n", c.DockerHost)
	fmt.Fprintf(&b, "CAs (in order):\n")

	for i, name := range c.CAOrder {
		ca := c.CAs[name]
		marker := "PRODUCTION"
		switch ca.Environment {
		case EnvStaging:
			marker = "STAGING"
		case EnvCustom:
			marker = "CUSTOM"
		}
		fmt.Fprintf(&b, "  %d. %-16s [%s] %s\n", i+1, name, marker, ca.URL)
		if ca.Email != "" {
			fmt.Fprintf(&b, "     email: %s\n", ca.Email)
		}
		if ca.EABKid != "" {
			fmt.Fprintf(&b, "     EAB kid: %s (hmac: %s)\n", ca.EABKid, redact(ca.EABHMAC))
		}
	}
	return b.String()
}

func redact(s string) string {
	if s == "" {
		return "(unset)"
	}
	return "(set)"
}

// HTTPAddr returns the status endpoint address. It is shared by Load and the
// healthcheck subcommand, which must resolve the address without loading the
// rest of the configuration.
func HTTPAddr() string { return envDefault("HTTP_ADDR", ":8080") }

// --- env helpers ---

// env reads key, falling back to the file named by key_FILE. The trailing
// newline is stripped, matching lego's _FILE convention. Every setting goes
// through this so any variable can be supplied as a Docker secret.
func env(key string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	if p := os.Getenv(key + "_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimRight(string(b), "\r\n")
		}
	}
	return ""
}

func envDefault(key, def string) string {
	if v := env(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := env(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := env(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envMode(key string, def os.FileMode) os.FileMode {
	v := env(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		return def
	}
	return os.FileMode(n)
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := env(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", key, v, err)
	}
	return d, nil
}

func envDurationList(key string, def []time.Duration) ([]time.Duration, error) {
	v := env(key)
	if v == "" {
		return def, nil
	}
	var out []time.Duration
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		d, err := time.ParseDuration(part)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", key, part, err)
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return def, nil
	}
	return out, nil
}

// envKey converts a CA name into an env-var-safe fragment.
func envKey(name string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}
