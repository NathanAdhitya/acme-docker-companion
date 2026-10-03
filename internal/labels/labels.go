// Package labels parses acmed.* container labels into certificate requests.
//
// A container may request one or many certificates. Bare labels define a
// default certificate (when they include acmed.domains/acmed.path) and
// container-wide defaults for reload/CA/key-type that every certificate
// inherits unless it overrides them.
package labels

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/go-acme/lego/v5/certcrypto"
	"golang.org/x/net/idna"
)

// Request is one certificate to obtain for a container.
type Request struct {
	// CertName is the label name segment ("" for the default certificate).
	CertName string
	// Domains is the normalized SAN list; the first entry is the CommonName.
	Domains []string
	// Path is the absolute directory inside the target container that will
	// receive the certificate files.
	Path string
	// ManagerPath overrides automatic bind-mount resolution.
	ManagerPath string
	// ReloadCmd is run inside the target after files change.
	ReloadCmd string
	// ReloadSignal is sent to PID 1 of the target after files change.
	ReloadSignal string
	// CAs is an optional ordered CA override.
	CAs []string
	// KeyType is an optional per-certificate key type.
	KeyType certcrypto.KeyType
	// Enabled is false when acmed.enable=false.
	Enabled bool
}

// certNameRe restricts certificate name segments.
var certNameRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

var simpleFields = map[string]bool{
	"domains":      true,
	"path":         true,
	"ca":           true,
	"key-type":     true,
	"manager-path": true,
	"enable":       true,
}

// allowedSignals is the set of signal names accepted for reload.signal.
var allowedSignals = map[string]bool{
	"SIGHUP": true, "SIGINT": true, "SIGTERM": true, "SIGQUIT": true,
	"SIGUSR1": true, "SIGUSR2": true, "SIGABRT": true, "SIGALRM": true,
	"SIGWINCH": true, "SIGKILL": true, "SIGSTOP": true, "SIGCONT": true,
}

type rawCert struct {
	name string
	kv   map[string]string
}

// defaults are container-wide values inherited by every certificate in the
// container unless the certificate sets its own.
type defaults struct {
	reloadCmd    string
	reloadSignal string
	cas          []string
	keyType      certcrypto.KeyType
}

// Parse extracts certificate requests from a container's labels. defaultKeyType
// is the global ACME_KEY_TYPE, applied to every certificate that does not set
// its own acmed.key-type.
//
// Problems are returned as warnings rather than errors: a malformed label must
// never take down the manager or affect other containers. Requests that cannot
// be made valid are omitted.
func Parse(prefix string, lbls map[string]string, defaultKeyType certcrypto.KeyType) (requests []Request, warnings []string) {
	if prefix == "" {
		prefix = "acmed"
	}
	dotPrefix := prefix + "."

	grouped := map[string]*rawCert{}
	var order []string

	for key, value := range lbls {
		if !strings.HasPrefix(key, dotPrefix) {
			continue
		}
		rest := strings.TrimPrefix(key, dotPrefix)
		name, field, ok := splitKey(rest)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("label %q: unrecognized acmed label", key))
			continue
		}
		rc := grouped[name]
		if rc == nil {
			rc = &rawCert{name: name, kv: map[string]string{}}
			grouped[name] = rc
			order = append(order, name)
		}
		rc.kv[field] = strings.TrimSpace(value)
	}

	sort.Strings(order)

	bare := grouped[""]
	def, defWarnings := parseDefaults(bare, defaultKeyType)
	warnings = append(warnings, defWarnings...)

	// acmed.enable=false on the bare labels opts the whole container out.
	if bare != nil {
		if v, ok := bare.kv["enable"]; ok {
			enabled, err := parseEnabled(v)
			if err != nil {
				warnings = append(warnings, "container: "+err.Error())
			} else if !enabled {
				return nil, warnings
			}
		}
	}

	type candidate struct {
		name string
		rc   *rawCert
	}
	var candidates []candidate

	// The bare labels define the default certificate only when they carry a
	// domains or path value.
	if bare != nil && (bare.kv["domains"] != "" || bare.kv["path"] != "") {
		candidates = append(candidates, candidate{name: "", rc: bare})
	}
	for _, name := range order {
		if name == "" {
			continue
		}
		candidates = append(candidates, candidate{name: name, rc: grouped[name]})
	}

	if len(candidates) == 0 {
		if bare != nil && len(bare.kv) > 0 {
			warnings = append(warnings, "container sets acmed defaults but defines no certificates (acmed.domains is required)")
		}
		return nil, warnings
	}

	seenPaths := map[string]string{} // path -> cert name
	for _, c := range candidates {
		req, errs := buildRequest(c.name, c.rc, def)
		if len(errs) > 0 {
			for _, e := range errs {
				warnings = append(warnings, fmt.Sprintf("certificate %q: %s", DisplayName(c.name), e))
			}
			continue
		}
		if !req.Enabled {
			continue
		}
		if prev, dup := seenPaths[req.Path]; dup {
			warnings = append(warnings, fmt.Sprintf("certificate %q: path %s is already used by %q; each certificate needs its own directory", DisplayName(c.name), req.Path, DisplayName(prev)))
			continue
		}
		seenPaths[req.Path] = c.name
		requests = append(requests, req)
	}
	return requests, warnings
}

// DisplayName renders a certificate name for humans; the empty name is the
// container's default certificate.
func DisplayName(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

// splitKey splits the part after the prefix into a certificate name and a
// field name. The default certificate uses the empty name.
func splitKey(rest string) (name, field string, ok bool) {
	if rest == "reload.cmd" || rest == "reload.signal" {
		return "", rest, true
	}
	if simpleFields[rest] {
		return "", rest, true
	}
	candidate, f, found := strings.Cut(rest, ".")
	if !found || !certNameRe.MatchString(candidate) {
		return "", "", false
	}
	if f == "reload.cmd" || f == "reload.signal" || simpleFields[f] {
		return candidate, f, true
	}
	return "", "", false
}

// parseDefaults reads the container-wide defaults from the bare labels. The
// global key type is the starting default; a bare acmed.key-type overrides it.
func parseDefaults(bare *rawCert, defaultKeyType certcrypto.KeyType) (defaults, []string) {
	d := defaults{keyType: defaultKeyType}
	var warnings []string
	if bare == nil {
		return d, nil
	}

	d.reloadCmd = bare.kv["reload.cmd"]
	d.reloadSignal = strings.ToUpper(bare.kv["reload.signal"])
	if d.reloadCmd != "" && d.reloadSignal != "" {
		warnings = append(warnings, "acmed.reload.cmd and acmed.reload.signal are mutually exclusive; ignoring both as defaults")
		d.reloadCmd, d.reloadSignal = "", ""
	}
	if d.reloadSignal != "" && !allowedSignals[d.reloadSignal] {
		warnings = append(warnings, fmt.Sprintf("invalid acmed.reload.signal %q", d.reloadSignal))
		d.reloadSignal = ""
	}
	d.cas = splitCA(bare.kv["ca"])
	if v := bare.kv["key-type"]; v != "" {
		kt, err := certcrypto.ToKeyType(v)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("invalid acmed.key-type %q: %s", v, err))
		} else {
			d.keyType = kt
		}
	}
	return d, warnings
}

func buildRequest(name string, rc *rawCert, def defaults) (Request, []string) {
	var errs []string
	req := Request{
		CertName:    name,
		Enabled:     true,
		Path:        rc.kv["path"],
		ManagerPath: rc.kv["manager-path"],
	}

	// Reload: a per-certificate action replaces the inherited default entirely.
	req.ReloadCmd = rc.kv["reload.cmd"]
	req.ReloadSignal = strings.ToUpper(rc.kv["reload.signal"])
	if req.ReloadCmd == "" && req.ReloadSignal == "" {
		req.ReloadCmd, req.ReloadSignal = def.reloadCmd, def.reloadSignal
	}
	if req.ReloadCmd != "" && req.ReloadSignal != "" {
		errs = append(errs, "acmed.reload.cmd and acmed.reload.signal are mutually exclusive")
	}
	if req.ReloadSignal != "" && !allowedSignals[req.ReloadSignal] {
		errs = append(errs, fmt.Sprintf("invalid acmed.reload.signal %q", req.ReloadSignal))
	}

	if v, ok := rc.kv["enable"]; ok {
		enabled, err := parseEnabled(v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			req.Enabled = enabled
		}
	}

	rawDomains := rc.kv["domains"]
	if rawDomains == "" {
		errs = append(errs, "acmed.domains is required")
	} else {
		domains, derr := normalizeDomains(rawDomains)
		if derr != nil {
			errs = append(errs, derr.Error())
		} else {
			req.Domains = domains
		}
	}

	if req.Path == "" {
		errs = append(errs, "acmed.path is required")
	} else if !path.IsAbs(req.Path) {
		errs = append(errs, fmt.Sprintf("acmed.path %q must be absolute", req.Path))
	} else {
		req.Path = path.Clean(req.Path)
	}

	if req.ManagerPath != "" && !path.IsAbs(req.ManagerPath) {
		errs = append(errs, fmt.Sprintf("acmed.manager-path %q must be absolute", req.ManagerPath))
	}

	// CA order and key type: per-certificate override, else container default.
	if v := rc.kv["ca"]; v != "" {
		req.CAs = splitCA(v)
	} else {
		req.CAs = def.cas
	}
	if v := rc.kv["key-type"]; v != "" {
		kt, kerr := certcrypto.ToKeyType(v)
		if kerr != nil {
			errs = append(errs, fmt.Sprintf("invalid acmed.key-type %q: %s", v, kerr))
		} else {
			req.KeyType = kt
		}
	} else {
		req.KeyType = def.keyType
	}

	return req, errs
}

func parseEnabled(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return false, nil
	case "true", "1", "yes", "on", "":
		return true, nil
	default:
		return true, fmt.Errorf("invalid enable value %q", v)
	}
}

func splitCA(v string) []string {
	var out []string
	for _, n := range strings.Split(v, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// normalizeDomains lowercases, IDNA-encodes, de-duplicates and validates a
// comma separated domain list, preserving order.
func normalizeDomains(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		d := strings.TrimSpace(part)
		if d == "" {
			continue
		}
		nd, err := NormalizeDomain(d)
		if err != nil {
			return nil, err
		}
		if !seen[nd] {
			seen[nd] = true
			out = append(out, nd)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("acmed.domains contains no valid domains")
	}
	return out, nil
}

// NormalizeDomain lowercases, trims a trailing dot, punycode-encodes and
// validates a single domain. A leading wildcard label is preserved.
func NormalizeDomain(domain string) (string, error) {
	d := strings.TrimSpace(strings.ToLower(domain))
	d = strings.TrimSuffix(d, ".")

	wildcard := false
	if strings.HasPrefix(d, "*.") {
		wildcard = true
		d = strings.TrimPrefix(d, "*.")
	}
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if strings.Contains(d, "*") {
		return "", fmt.Errorf("wildcard %q is only allowed as the leftmost label", domain)
	}

	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	if !validDomain(ascii) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if wildcard {
		return "*." + ascii, nil
	}
	return ascii, nil
}

// validDomain checks the shape requirements IDNA does not enforce: at least
// two labels, no empty labels, and DNS length limits. Character and hyphen
// rules are already enforced by idna.Lookup in NormalizeDomain.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
	}
	return true
}
