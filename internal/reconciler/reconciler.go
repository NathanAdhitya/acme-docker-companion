// Package reconciler turns labeled containers into certificate requests,
// issues/renews them, delivers files through bind mounts, and triggers reloads.
package reconciler

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"

	"github.com/NathanAdhitya/acme-docker-companion/internal/acmex"
	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
	"github.com/NathanAdhitya/acme-docker-companion/internal/delivery"
	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/labels"
	"github.com/NathanAdhitya/acme-docker-companion/internal/scheduler"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

const (
	resyncInterval = 10 * time.Minute
	dueInterval    = 1 * time.Minute
	gcInterval     = 6 * time.Hour
	// reloadTimeout bounds a reload command run inside a target.
	reloadTimeout = 30 * time.Second
)

// Reconciler owns the demand set and the issuance pipeline.
//
// Live state (certs, warnings, ...) is owned by the main loop goroutine:
// resync and process run sequentially, and process waits for every certificate
// worker before returning. Snapshot never reads live state; it serves the
// status published at the end of a cycle, so /healthz cannot block behind an
// in-flight issuance (D5).
type Reconciler struct {
	cfg    *config.Config
	docker dockerx.Client
	issuer acmex.Issuer
	store  *store.Store
	log    *slog.Logger
	now    func() time.Time

	sem     chan struct{}
	trigger chan struct{}

	watcherUp atomic.Bool
	status    atomic.Pointer[Status]

	certs      map[string]*certState
	warnings   []string
	lastResync time.Time
	lastGC     time.Time
	selfKnown  bool
	selfWarned bool
}

// cycle is the per-reconcile-cycle state shared by the certificate workers:
// reload actions already executed this cycle, so certificates of one container
// that share an action reload it once.
type cycle struct {
	mu      sync.Mutex
	reloads map[string]error
}

// certState is one certificate's live state. Identity, scheduling, ARI and
// failure state all live in cert.Meta — the same struct that is persisted — so
// there is a single source of truth. cert is always non-nil; its PEM material
// is empty until the certificate is issued.
type certState struct {
	id         string
	candidates []string
	cert       *store.Cert
	leaf       *x509.Certificate
	targets    map[string]*targetState
}

type targetState struct {
	containerID   string
	containerName string
	path          string
	managerPath   string
	reloadCmd     string
	reloadSignal  string

	misconfigured string

	delivered     bool
	pendingReload bool
	reloadState   string
	lastErr       string
	warnedNoLoad  bool

	// stale marks a target for removal at the end of a resync.
	stale bool
}

// New builds a Reconciler.
func New(cfg *config.Config, docker dockerx.Client, issuer acmex.Issuer, st *store.Store, log *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:     cfg,
		docker:  docker,
		issuer:  issuer,
		store:   st,
		log:     log,
		now:     func() time.Time { return time.Now().UTC() },
		sem:     make(chan struct{}, cfg.MaxConcurrentIssuance),
		trigger: make(chan struct{}, 1),
		certs:   map[string]*certState{},
	}
}

// Run performs an initial reconcile then watches events and the clock until
// the context is cancelled.
func (r *Reconciler) Run(ctx context.Context) {
	// Subscription starts at the scan start so containers that appear during
	// the initial scan are not missed (D8).
	since := r.now()
	r.cycle(ctx)

	go r.watchEvents(ctx, since)

	resyncT := time.NewTicker(resyncInterval)
	dueT := time.NewTicker(dueInterval)
	defer resyncT.Stop()
	defer dueT.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
			r.cycle(ctx)
		case <-resyncT.C:
			r.cycle(ctx)
		case <-dueT.C:
			r.process(ctx)
			r.publish()
		}
	}
}

// cycle rebuilds the demand set from Docker, reconciles it, and publishes the
// status document.
func (r *Reconciler) cycle(ctx context.Context) {
	r.resync(ctx)
	r.process(ctx)
	r.publish()
}

// Once runs a single reconcile + process cycle (used by --once).
func (r *Reconciler) Once(ctx context.Context) {
	r.cycle(ctx)
}

func (r *Reconciler) triggerOnce() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

func (r *Reconciler) watchEvents(ctx context.Context, since time.Time) {
	backoff := time.Second
	for ctx.Err() == nil {
		events, errs := r.docker.Events(ctx, since)
		r.watcherUp.Store(true)

		disconnected := false
		for !disconnected && ctx.Err() == nil {
			select {
			case <-ctx.Done():
				disconnected = true
			case _, ok := <-events:
				if !ok {
					disconnected = true
					break
				}
				backoff = time.Second // a live stream resets the reconnect ladder
				r.triggerOnce()
			case err, ok := <-errs:
				if !ok {
					disconnected = true
					break
				}
				if err != nil {
					r.log.Warn("docker event stream disconnected; resyncing", "error", err)
				}
				disconnected = true
				break
			}
		}
		r.watcherUp.Store(false)
		if ctx.Err() != nil {
			return
		}
		// The triggered resync covers the gap while disconnected; replaying
		// the stream from just before it makes the new subscription race-free
		// relative to that scan.
		since = r.now()
		r.triggerOnce()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// resync rebuilds the demand set from the Docker API. It runs on the main loop
// between process cycles, so it can mutate certState in place without locking;
// certificate workers only run inside process.
func (r *Reconciler) resync(ctx context.Context) {
	containers, err := r.docker.List(ctx)
	if err != nil {
		r.log.Error("list containers failed", "error", err)
		r.watcherUp.Store(false)
		return
	}

	self, ok := r.docker.Self(ctx)
	var selfMounts []dockerx.Mount
	if ok {
		selfMounts = self.Mounts
	}

	var warnings []string
	seenWarn := map[string]bool{}
	addWarn := func(msg string) {
		if !seenWarn[msg] {
			seenWarn[msg] = true
			warnings = append(warnings, msg)
		}
	}

	// Every target is stale until the parse below finds it again.
	for _, cs := range r.certs {
		for _, t := range cs.targets {
			t.stale = true
		}
	}

	// CA candidates are resolved from this cycle's requests and refreshed each
	// resync, so a container recreated with a different acmed.ca is honoured
	// without a restart. When containers disagree about one certificate's
	// override, the lexicographically smallest list wins, making the choice
	// independent of Docker's container order.
	chosen := map[string][]string{}

	referenced := map[string]bool{}
	for _, c := range containers {
		if ok && c.ID == self.ID {
			continue
		}
		reqs, warns := labels.Parse(r.cfg.LabelPrefix, c.Labels, r.cfg.KeyType)
		for _, w := range warns {
			addWarn(fmt.Sprintf("container %s: %s", c.Name, w))
		}
		for _, req := range reqs {
			id := store.CertID(req.Domains, req.KeyType, r.cfg.Profile)

			cands, cw := r.cfg.ResolveCandidates(req.CAs)
			for _, w := range cw {
				addWarn(fmt.Sprintf("container %s: %s", c.Name, w))
			}
			if len(cands) == 0 {
				addWarn(fmt.Sprintf("container %s: certificate %q has no usable CA candidates", c.Name, strings.Join(req.Domains, ",")))
				continue
			}
			if prev, seen := chosen[id]; !seen || lessCandidates(cands, prev) {
				chosen[id] = cands
			}

			cs := r.certs[id]
			if cs == nil {
				cs = &certState{
					id: id,
					cert: &store.Cert{ID: id, Meta: store.Meta{
						ID:             id,
						Domains:        req.Domains,
						KeyType:        string(req.KeyType),
						Profile:        r.cfg.Profile,
						PreferredChain: r.cfg.PreferredChain,
					}},
					targets: map[string]*targetState{},
				}
				r.loadCached(cs)
				r.certs[id] = cs
			}
			cs.candidates = chosen[id]
			referenced[id] = true

			// Surviving targets keep their delivery/reload state; new ones
			// start undelivered.
			key := c.ID + "|" + req.Path
			t := cs.targets[key]
			if t == nil {
				t = &targetState{containerID: c.ID}
				cs.targets[key] = t
			}
			t.stale = false
			t.containerName = c.Name
			t.path = req.Path
			t.reloadCmd = req.ReloadCmd
			t.reloadSignal = req.ReloadSignal
			t.managerPath = ""
			t.misconfigured = ""
			if req.ManagerPath != "" {
				t.managerPath = req.ManagerPath
			} else if mp, rerr := delivery.Resolve(c.Mounts, req.Path, selfMounts); rerr != nil {
				t.misconfigured = rerr.Error()
				addWarn(fmt.Sprintf("container %s: certificate %q: %s", c.Name, strings.Join(req.Domains, ","), rerr))
			} else {
				t.managerPath = mp
			}
		}
	}

	for id, cs := range r.certs {
		if !referenced[id] {
			delete(r.certs, id)
			continue
		}
		for key, t := range cs.targets {
			if t.stale {
				delete(cs.targets, key)
			}
		}
	}
	r.warnings = warnings
	r.lastResync = r.now()
	r.selfKnown = ok

	if !ok && !r.selfWarned {
		r.selfWarned = true
		r.log.Warn("could not identify the acmed container; automatic bind-mount mapping is disabled. Set acmed.manager-path on targets or ensure HOSTNAME is the container id")
	}

	r.gc(r.now(), referenced)
}

// lessCandidates orders CA candidate lists deterministically. It is used to
// pick one list when several containers request the same certificate with
// different acmed.ca overrides.
func lessCandidates(a, b []string) bool {
	return strings.Join(a, ",") < strings.Join(b, ",")
}

// loadCached restores persisted certificate, ARI and failure state on first
// sight.
func (r *Reconciler) loadCached(cs *certState) {
	cert, err := r.store.LoadCert(cs.id)
	if err != nil || cert == nil {
		return
	}
	cs.cert = cert
	cs.leaf = parseLeaf(cert.CertPEM)
}

// gc removes expired certificates that no running container references.
func (r *Reconciler) gc(now time.Time, referenced map[string]bool) {
	if !r.lastGC.IsZero() && now.Sub(r.lastGC) < gcInterval {
		return
	}
	r.lastGC = now

	cached, err := r.store.ListCerts()
	if err != nil {
		r.log.Warn("certificate GC: list failed", "error", err)
		return
	}
	for _, c := range cached {
		if referenced[c.ID] {
			continue
		}
		if c.Meta.NotAfter.IsZero() || !c.Meta.NotAfter.Before(now) {
			continue
		}
		if err := r.store.DeleteCert(c.ID); err != nil {
			r.log.Warn("certificate GC: delete failed", "cert", c.ID, "error", err)
			continue
		}
		r.log.Info("removed expired unreferenced certificate", "cert", c.ID)
	}
}

func (r *Reconciler) process(ctx context.Context) {
	cyc := &cycle{reloads: map[string]error{}}

	// r.certs is only mutated by resync on this goroutine, so the workers can
	// range it directly.
	var wg sync.WaitGroup
	for _, cs := range r.certs {
		wg.Add(1)
		go func(cs *certState) {
			defer wg.Done()
			r.processCert(ctx, cs, cyc)
		}(cs)
	}
	wg.Wait()
}

func (r *Reconciler) processCert(ctx context.Context, cs *certState, cyc *cycle) {
	now := r.now()
	usable := cs.cacheValid()
	m := &cs.cert.Meta

	// Refresh ARI for a usable certificate and draw the renewal instant once
	// per window (RFC 9773). Re-drawing on every tick would bias renewal to
	// the start of the window; a nil draw waits for the next refresh.
	if usable && m.IssuerCA != "" {
		if m.ARICheckedAt.IsZero() || now.Sub(m.ARICheckedAt) >= r.ariRefreshAfter(cs) {
			window, err := r.issuer.RenewalInfo(ctx, m.IssuerCA, cs.leaf)
			m.ARICheckedAt = now
			m.ARIValid = false
			m.ARIRetryAfter = 0
			m.ARIRenewAt = time.Time{}
			if err != nil {
				r.log.Warn("ARI query failed; using the lifetime rule", "cert", cs.id, "ca", m.IssuerCA, "error", err)
			} else if window != nil {
				m.ARIRetryAfter = window.RetryAfter
				m.ARIValid = true
				if at := window.ShouldRenewAt(now, r.cfg.CheckInterval); at != nil {
					m.ARIRenewAt = *at
				}
			}
		}
	}

	sched := r.schedCfg()
	st := cs.schedState()
	st.ForceRenew = !usable
	if scheduler.ShouldRenew(now, st, sched) {
		if err := r.issue(ctx, cs); err != nil {
			if errors.Is(err, acmex.ErrCoolingDown) {
				// No order was attempted, so do not grow the failure backoff;
				// the next tick retries once a cooldown lapses.
				m.LastError = err.Error()
				r.log.Info("issuance deferred; all candidate CAs are cooling down", "cert", cs.id, "error", err)
			} else {
				m.ConsecutiveFailures++
				m.LastAttempt = now
				m.LastError = err.Error()
				m.NextAttempt = now.Add(scheduler.BackoffDuration(m.ConsecutiveFailures, sched))
				r.log.Error("certificate issuance failed", "cert", cs.id, "domains", strings.Join(m.Domains, ","), "failures", m.ConsecutiveFailures, "error", err)
			}
			r.persist(cs)
		}
	}

	// Deliver only when something usable is cached; there is nothing to write
	// for an absent certificate.
	if cs.cacheValid() {
		r.deliver(ctx, cs, cyc)
	}
}

// cacheValid reports whether a usable certificate is cached. It is
// deliberately issuer-agnostic: a certificate issued by a previous candidate
// keeps serving until it is due, so CA or staging changes never force
// reissuance (the cache protects ACME rate limits). The private key is part of
// validity: delivering a keyless certificate would remove the target's key.
func (cs *certState) cacheValid() bool {
	return cs.leaf != nil && len(cs.cert.Fullchain) > 0 && len(cs.cert.Privkey) > 0
}

// ariRefreshAfter is how long to wait before querying ARI again: our own
// check cadence, stretched when the server asked for a longer Retry-After.
func (r *Reconciler) ariRefreshAfter(cs *certState) time.Duration {
	d := r.cfg.CheckInterval
	if m := cs.cert.Meta; m.ARIValid && m.ARIRetryAfter > d {
		d = m.ARIRetryAfter
	}
	return d
}

func (r *Reconciler) issue(ctx context.Context, cs *certState) error {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	m := &cs.cert.Meta
	req := acmex.IssueRequest{
		Domains:        m.Domains,
		KeyType:        certcrypto.KeyType(m.KeyType),
		Profile:        m.Profile,
		PreferredChain: m.PreferredChain,
		Candidates:     cs.candidates,
	}
	// The manager renews in place only against the CA endpoint that issued the
	// cached certificate; every other candidate gets a fresh order.
	if m.IssuerCA != "" {
		req.Prev = &acmex.PrevCert{
			IssuerCA:  m.IssuerCA,
			IssuerURL: m.IssuerURL,
			CertPEM:   cs.cert.Fullchain,
			KeyPEM:    cs.cert.Privkey,
		}
	}

	res, err := r.issuer.Issue(ctx, req)
	if err != nil {
		return err
	}

	now := r.now()
	cs.cert.Fullchain = res.FullchainPEM
	cs.cert.Privkey = res.KeyPEM
	cs.cert.CertPEM = res.LeafPEM
	cs.cert.Chain = res.ChainPEM
	m.IssuerCA = res.IssuerCA
	m.IssuerURL = res.IssuerURL
	m.CertURL = res.CertURL
	m.NotBefore = res.NotBefore
	m.NotAfter = res.NotAfter
	m.ObtainedAt = now
	m.ConsecutiveFailures = 0
	m.LastAttempt = now
	m.LastError = ""
	m.NextAttempt = time.Time{}
	m.ARIValid = false
	m.ARIRetryAfter = 0
	m.ARIRenewAt = time.Time{}
	m.ARICheckedAt = time.Time{}

	if err := r.store.SaveCert(cs.cert, r.cfg.FileUID, r.cfg.FileGID, r.cfg.FileMode, r.cfg.KeyMode); err != nil {
		return fmt.Errorf("persist certificate: %w", err)
	}
	cs.leaf = parseLeaf(res.LeafPEM)

	r.log.Info("certificate issued",
		"cert", cs.id,
		"domains", strings.Join(m.Domains, ","),
		"ca", res.IssuerCA,
		"notAfter", res.NotAfter.Format(time.RFC3339))
	return nil
}

func (r *Reconciler) deliver(ctx context.Context, cs *certState, cyc *cycle) {
	if r.cfg.DryRun {
		return
	}
	opts := delivery.Options{
		UID:      r.cfg.FileUID,
		GID:      r.cfg.FileGID,
		CertMode: r.cfg.FileMode,
		KeyMode:  r.cfg.KeyMode,
	}

	for _, t := range cs.targets {
		if t.misconfigured != "" {
			t.reloadState = "misconfigured"
			continue
		}

		// Writes are idempotent: WriteCert reports whether content changed, so
		// there is no separate "needs delivery" flag and a failed write is
		// naturally retried on the next cycle.
		changed, err := delivery.WriteCert(t.managerPath, cs.cert, opts)
		if err != nil {
			t.delivered = false
			t.lastErr = err.Error()
			r.log.Error("delivery failed", "container", t.containerName, "cert", cs.id, "path", t.path, "error", err)
			continue
		}
		t.delivered = true
		if changed {
			t.pendingReload = true
		}
		if !t.pendingReload {
			if t.reloadState == "" {
				t.reloadState = "none"
			}
			continue
		}

		if t.reloadCmd == "" && t.reloadSignal == "" {
			t.reloadState = "none"
			t.pendingReload = false
			if !t.warnedNoLoad {
				t.warnedNoLoad = true
				r.log.Warn("certificate delivered without a reload command or signal; the application may keep serving the old certificate until it restarts",
					"container", t.containerName, "cert", cs.id, "path", t.path)
			}
			continue
		}

		r.runReload(ctx, cs, t, cyc)
	}
}

// runReload executes a target's reload action at most once per reconcile
// cycle. Several certificates of the same container that share an action
// (e.g. inherited from a container default) trigger a single reload; each
// target still records the shared outcome.
func (r *Reconciler) runReload(ctx context.Context, cs *certState, t *targetState, cyc *cycle) {
	kind, value := "cmd", t.reloadCmd
	if t.reloadSignal != "" {
		kind, value = "signal", t.reloadSignal
	}
	key := t.containerID + "|" + kind + "|" + value

	cyc.mu.Lock()
	outcome, done := cyc.reloads[key]
	if !done {
		switch kind {
		case "cmd":
			_, outcome = r.docker.Exec(ctx, t.containerID, []string{"/bin/sh", "-c", value}, reloadTimeout)
		case "signal":
			outcome = r.docker.Kill(ctx, t.containerID, value)
		}
		cyc.reloads[key] = outcome
	}
	cyc.mu.Unlock()

	if outcome != nil {
		t.reloadState = "failed"
		t.pendingReload = true
		t.lastErr = outcome.Error()
		r.log.Error("reload failed", "container", t.containerName, "cert", cs.id, "error", outcome)
		return
	}
	t.reloadState = "ok"
	t.pendingReload = false
	t.lastErr = ""
	r.log.Info("certificate delivered and reloaded", "container", t.containerName, "cert", cs.id, "path", t.path)
}

func (cs *certState) schedState() scheduler.State {
	m := &cs.cert.Meta
	return scheduler.State{
		NotBefore:   m.NotBefore,
		NotAfter:    m.NotAfter,
		ARI:         m.ARIValid,
		RenewAt:     m.ARIRenewAt,
		NextAttempt: m.NextAttempt,
	}
}

func (r *Reconciler) schedCfg() scheduler.Config {
	return scheduler.Config{
		RenewBefore: r.cfg.RenewBefore,
		Backoff:     r.cfg.FailureBackoff,
	}
}

// persist writes the certificate's current state (identity, failure/backoff
// and ARI) to disk. The PEM files are written only when present, so a
// never-issued certificate keeps its backoff across restarts.
func (r *Reconciler) persist(cs *certState) {
	if err := r.store.SaveCert(cs.cert, r.cfg.FileUID, r.cfg.FileGID, r.cfg.FileMode, r.cfg.KeyMode); err != nil {
		r.log.Error("persist certificate state failed", "cert", cs.id, "error", err)
	}
}

func parseLeaf(pemBytes []byte) *x509.Certificate {
	c, err := certcrypto.ParsePEMCertificate(pemBytes)
	if err != nil {
		return nil
	}
	return c
}

// --- status ---

// Status is the JSON document served at /healthz.
type Status struct {
	WatcherConnected bool         `json:"watcherConnected"`
	SelfKnown        bool         `json:"selfKnown"`
	LastResync       time.Time    `json:"lastResync"`
	DryRun           bool         `json:"dryRun"`
	CAOrder          []string     `json:"caOrder"`
	Warnings         []string     `json:"warnings,omitempty"`
	Certs            []CertStatus `json:"certs"`
}

// CertStatus describes one certificate and its targets.
type CertStatus struct {
	ID          string         `json:"id"`
	Domains     []string       `json:"domains"`
	KeyType     string         `json:"keyType"`
	Profile     string         `json:"profile,omitempty"`
	Candidates  []string       `json:"candidates"`
	Issuer      string         `json:"issuer,omitempty"`
	IssuerURL   string         `json:"issuerURL,omitempty"`
	NotAfter    time.Time      `json:"notAfter,omitempty"`
	NextAttempt time.Time      `json:"nextAttempt,omitempty"`
	LastError   string         `json:"lastError,omitempty"`
	Targets     []TargetStatus `json:"targets"`
}

// TargetStatus describes delivery/reload state for one container.
type TargetStatus struct {
	Container   string `json:"container"`
	Path        string `json:"path"`
	ManagerPath string `json:"managerPath,omitempty"`
	Delivered   bool   `json:"delivered"`
	Reload      string `json:"reload"`
	Error       string `json:"error,omitempty"`
}

// publish assembles the status document from live state and stores it for
// Snapshot. It must run on the main loop goroutine, after process has
// returned, when no certificate worker is mutating state.
func (r *Reconciler) publish() {
	st := Status{
		WatcherConnected: r.watcherUp.Load(),
		SelfKnown:        r.selfKnown,
		LastResync:       r.lastResync,
		DryRun:           r.cfg.DryRun,
		CAOrder:          slices.Clone(r.cfg.CAOrder),
		Warnings:         slices.Clone(r.warnings),
	}
	for _, id := range slices.Sorted(maps.Keys(r.certs)) {
		cs := r.certs[id]
		m := &cs.cert.Meta
		csStatus := CertStatus{
			ID:          cs.id,
			Domains:     slices.Clone(m.Domains),
			KeyType:     m.KeyType,
			Profile:     m.Profile,
			Candidates:  slices.Clone(cs.candidates),
			Issuer:      m.IssuerCA,
			IssuerURL:   m.IssuerURL,
			NotAfter:    m.NotAfter,
			NextAttempt: m.NextAttempt,
			LastError:   m.LastError,
		}
		for _, k := range slices.Sorted(maps.Keys(cs.targets)) {
			t := cs.targets[k]
			csStatus.Targets = append(csStatus.Targets, TargetStatus{
				Container:   t.containerName,
				Path:        t.path,
				ManagerPath: t.managerPath,
				Delivered:   t.delivered,
				Reload:      t.reloadState,
				Error:       t.lastErr,
			})
		}
		st.Certs = append(st.Certs, csStatus)
	}
	r.status.Store(&st)
}

// Snapshot returns the status published at the end of the last cycle. It never
// reads live state, so it cannot block behind an in-flight issuance.
func (r *Reconciler) Snapshot() Status {
	published := r.status.Load()
	if published == nil {
		return Status{DryRun: r.cfg.DryRun, CAOrder: slices.Clone(r.cfg.CAOrder)}
	}
	st := *published
	st.WatcherConnected = r.watcherUp.Load()
	return st
}
