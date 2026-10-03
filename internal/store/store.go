// Package store persists ACME accounts and issued certificates with atomic,
// durable writes, and enforces single-instance operation with a lock file.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"golang.org/x/sys/unix"

	"github.com/NathanAdhitya/acme-docker-companion/internal/fsutil"
)

// File names written into every certificate directory.
const (
	FileFullchain = "fullchain.pem"
	FilePrivkey   = "privkey.pem"
	FileCert      = "cert.pem"
	FileChain     = "chain.pem"
	fileMeta      = "meta.json"
)

// Meta is the persistent metadata for one cached certificate.
type Meta struct {
	ID             string    `json:"id"`
	Domains        []string  `json:"domains"`
	KeyType        string    `json:"keyType"`
	Profile        string    `json:"profile,omitempty"`
	PreferredChain string    `json:"preferredChain,omitempty"`
	IssuerCA       string    `json:"issuerCA,omitempty"`
	IssuerURL      string    `json:"issuerURL,omitempty"`
	CertURL        string    `json:"certURL,omitempty"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	ObtainedAt     time.Time `json:"obtainedAt"`

	ConsecutiveFailures int       `json:"consecutiveFailures,omitempty"`
	LastAttempt         time.Time `json:"lastAttempt,omitempty"`
	NextAttempt         time.Time `json:"nextAttempt,omitempty"`
	LastError           string    `json:"lastError,omitempty"`

	ARIValid      bool          `json:"ariValid,omitempty"`
	ARIRetryAfter time.Duration `json:"ariRetryAfter,omitempty"`
	ARIRenewAt    time.Time     `json:"ariRenewAt,omitempty"`
	ARICheckedAt  time.Time     `json:"ariCheckedAt,omitempty"`
}

// Cert is a cached certificate and its PEM material.
type Cert struct {
	ID        string
	Meta      Meta
	Fullchain []byte
	Privkey   []byte
	CertPEM   []byte
	Chain     []byte
}

// File is one certificate file in the fixed set of DESIGN Appendix B: its
// name, content and mode. Data is nil for a file the certificate does not have
// (e.g. a chain with no intermediates), which lets callers remove a stale copy.
type File struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// CertFiles lists a certificate's files in the fixed order of DESIGN
// Appendix B, with the certificate and key modes applied.
func CertFiles(c *Cert, certMode, keyMode os.FileMode) []File {
	return []File{
		{FileFullchain, c.Fullchain, certMode},
		{FileCert, c.CertPEM, certMode},
		{FileChain, c.Chain, certMode},
		{FilePrivkey, c.Privkey, keyMode},
	}
}

// Store is the on-disk state directory.
type Store struct {
	dir  string
	lock *os.File
}

// Open prepares the state directory and takes the single-instance lock.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"", "accounts", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("create state dir: %w", err)
		}
	}

	lockPath := filepath.Join(dir, ".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another acmed instance is already using %s (lock held)", dir)
	}

	// Remove leftovers from a crash mid-write.
	_ = fsutil.CleanTemp(dir)

	return &Store{dir: dir, lock: f}, nil
}

// Close releases the lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}

// --- accounts ---

// accountRecord is the on-disk account document. It records the directory URL
// the registration belongs to, so switching a CA name between staging and
// production does not reuse the wrong account registration.
type accountRecord struct {
	DirectoryURL string          `json:"directoryURL"`
	Registration json.RawMessage `json:"registration,omitempty"`
}

// Account is a stored ACME account.
type Account struct {
	KeyPEM       []byte
	Registration []byte
	DirectoryURL string
}

// SaveAccount persists an account private key (PEM) and registration JSON.
func (s *Store) SaveAccount(caName, directoryURL string, keyPEM, registration []byte) error {
	dir := filepath.Join(s.dir, "accounts", caName)
	rec := accountRecord{DirectoryURL: directoryURL}
	if len(registration) > 0 {
		rec.Registration = registration
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account for %s: %w", caName, err)
	}
	if _, err := fsutil.WriteFileAtomic(filepath.Join(dir, "account.key"), keyPEM, 0o600, -1, -1); err != nil {
		return fmt.Errorf("save account key for %s: %w", caName, err)
	}
	if _, err := fsutil.WriteFileAtomic(filepath.Join(dir, "account.json"), data, 0o600, -1, -1); err != nil {
		return fmt.Errorf("save account registration for %s: %w", caName, err)
	}
	return nil
}

// LoadAccount reads a stored account. ok is false when none exists.
func (s *Store) LoadAccount(caName string) (Account, bool, error) {
	dir := filepath.Join(s.dir, "accounts", caName)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "account.key"))
	if err != nil {
		if os.IsNotExist(err) {
			return Account{}, false, nil
		}
		return Account{}, false, fmt.Errorf("read account key for %s: %w", caName, err)
	}

	acct := Account{KeyPEM: keyPEM}
	raw, err := os.ReadFile(filepath.Join(dir, "account.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return acct, true, nil
		}
		return Account{}, false, fmt.Errorf("read account registration for %s: %w", caName, err)
	}
	var rec accountRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return acct, true, nil
	}
	acct.Registration = rec.Registration
	acct.DirectoryURL = rec.DirectoryURL
	return acct, true, nil
}

// --- certificates ---

// CertID derives the stable cache identity for a certificate. It is
// intentionally independent of the issuing CA (the CA is recorded in meta and
// re-validated on reuse), but depends on key type and ACME profile.
func CertID(domains []string, keyType certcrypto.KeyType, profile string) string {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(strings.Join(sorted, "\x00")))
	h.Write([]byte("\x00" + string(keyType) + "\x00" + profile))
	sum := hex.EncodeToString(h.Sum(nil))
	primary := sanitizeDomain(sorted[0])
	return primary + "-" + sum[:12]
}

func sanitizeDomain(d string) string {
	d = strings.ReplaceAll(d, "*.", "wildcard.")
	var b strings.Builder
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// LoadCert reads a certificate by ID. It returns (nil, nil) when absent.
func (s *Store) LoadCert(id string) (*Cert, error) {
	dir := filepath.Join(s.dir, "certs", id)
	metaBytes, err := os.ReadFile(filepath.Join(dir, fileMeta))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read meta for %s: %w", id, err)
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("parse meta for %s: %w", id, err)
	}
	c := &Cert{ID: id, Meta: meta}
	c.Fullchain, _ = os.ReadFile(filepath.Join(dir, FileFullchain))
	c.Privkey, _ = os.ReadFile(filepath.Join(dir, FilePrivkey))
	c.CertPEM, _ = os.ReadFile(filepath.Join(dir, FileCert))
	c.Chain, _ = os.ReadFile(filepath.Join(dir, FileChain))
	return c, nil
}

// SaveCert writes the PEM files present in c and meta.json atomically. A
// certificate that has not been issued yet (no PEM material) persists just its
// meta, so failure/backoff state survives a restart.
func (s *Store) SaveCert(c *Cert, uid, gid int, certMode, keyMode os.FileMode) error {
	dir := filepath.Join(s.dir, "certs", c.ID)
	for _, f := range CertFiles(c, certMode, keyMode) {
		if len(f.Data) == 0 {
			continue
		}
		if _, err := fsutil.WriteFileAtomic(filepath.Join(dir, f.Name), f.Data, f.Mode, uid, gid); err != nil {
			return fmt.Errorf("write %s for %s: %w", f.Name, c.ID, err)
		}
	}
	metaBytes, err := json.MarshalIndent(&c.Meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode meta for %s: %w", c.ID, err)
	}
	if _, err := fsutil.WriteFileAtomic(filepath.Join(dir, fileMeta), metaBytes, 0o644, uid, gid); err != nil {
		return fmt.Errorf("write meta for %s: %w", c.ID, err)
	}
	return nil
}

// ListCerts loads every cached certificate.
func (s *Store) ListCerts() ([]*Cert, error) {
	root := filepath.Join(s.dir, "certs")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Cert
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := s.LoadCert(e.Name())
		if err != nil {
			continue
		}
		if c != nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// DeleteCert removes a certificate directory.
func (s *Store) DeleteCert(id string) error {
	return os.RemoveAll(filepath.Join(s.dir, "certs", id))
}
