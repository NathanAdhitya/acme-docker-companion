# acme-docker-companion — Design Document

Status: design; implementation complete and verified (see §20)
Last updated: 2026-10-03

This document describes **what acmed is and how it is designed to work**. It
replaces the earlier milestone-oriented plan.

---

## 1. Purpose

`acmed` is a single-purpose Docker sidecar that keeps TLS certificates fresh
for **many** containers. It watches the Docker socket for container labels,
obtains and renews certificates with [lego](https://github.com/go-acme/lego)
using **DNS-01 only**, writes them into bind-mounted directories, and reloads
the containers.

The unit of work is the **certificate**, not the container. A container may
request one or many certificates; a certificate may be requested by one or many
containers.

## 2. Goals and non-goals

Goals:

- Automatic issuance and renewal for many containers with minimal per-container
  configuration.
- Reliability first: never burn ACME rate limits, never serve an expired
  certificate, never crash on a bad label.
- Simplicity: one binary, one `.env`, a few labels; the common case (one CA,
  one DNS provider, one shared certificate volume) must be trivial.

Non-goals:

- HTTP-01 / TLS-ALPN-01 (DNS-01 only).
- `docker cp` delivery (bind mounts only).
- Revocation, certificate import/export, PFX output.
- Swarm / multi-host management, non-Linux containers.
- Prometheus metrics, webhook notifications (status endpoint + logs only).

## 3. Terminology

| Term | Meaning |
|---|---|
| **Manager** | The `acmed` process/container. |
| **Target** | A container that consumes a certificate. |
| **Cert request** | One certificate as requested by one container (labels → `Request`). |
| **Certificate** | The deduplicated issuance identity `(sorted domains, key type, profile)`. |
| **Delivery target** | A `(container, cert request)` pair: where a certificate is written and how that container is reloaded. |
| **Issuer** | The CA that signed a cached certificate (`meta.issuerCA` + `meta.issuerURL`). |
| **Candidate** | A configured CA in the ordered active/backup list. |

## 4. Architecture

```
Docker labels ─► parse ─► reconcile ─► ACME DNS-01 (lego) ─► write files ─► reload
```

```
Docker socket (unix/tcp)
        │
        ▼
  Watcher ──► Label parser ──► Reconciler ──► Scheduler (ARI + backoff)
  events+resync      │             │                    │
                     │             ▼                    ▼
                     │      Bind-mount delivery   ACME layer (lego v5)
                     │      (path mapping)        ├─ CA candidates (active/backup)
                     │             │              ├─ accounts per CA
                     │             ▼              └─ DNS-01 provider
                     │        Reload (exec|signal)
                     ▼
                Cert store (accounts/, certs/, meta.json)
```

Packages:

| Package | Responsibility |
|---|---|
| `internal/config` | env + `_FILE` loading, multi-CA parsing, validation, redacted dump |
| `internal/labels` | parse `acmed.*` labels → `[]CertRequest`, validation |
| `internal/dockerx` | moby client wrapper: list/inspect/events/exec/kill; self-mount map |
| `internal/store` | account + cert cache, atomic writes, `meta.json`, flock |
| `internal/acmex` | lego wrapper: clients per CA, account registration/EAB, obtain/renew, ARI |
| `internal/reconciler` | demand set, dedupe, single-flight, delivery orchestration |
| `internal/scheduler` | pure lifetime/backoff decision logic (clock injected); ARI windows delegated to lego |
| `internal/delivery` | mount-path resolution, atomic file writes |
| `internal/reload` | exec command / signal with a timeout |
| `internal/httpx` | `/healthz` JSON status |
| `cmd/acmed` | `run` (default), `check`, `healthcheck`, `--once`, `--dry-run` |

## 5. Certificate model

The central model of the design:

```
Container ──labels──► []CertRequest ──identity──► Certificate ──delivery──► []DeliveryTarget
```

- **One container → many cert requests.** Any number of certificates per
  container, each with its own domains, directory, and reload action.
- **Many containers → one certificate.** Cert requests with the same identity
  are deduplicated: the certificate is issued once and delivered to every
  container that requested it. This is a rate-limit safeguard and the reason
  sharing a wildcard certificate across services is cheap.
- **One certificate → many delivery targets.** Each target resolves its own
  host path through the bind mounts and records its own delivery/reload state.

Certificate identity:

```
certID = "<primary-domain>-<sha256(sorted domains | key type | profile)[:12]>"
```

Notes:

- Identity is **CA-independent**; the issuing CA is recorded in `meta.json` and
  used to route renewal (§8, decision D1).
- Sorted domains make the identity order-insensitive, so two containers listing
  the same SANs in a different order share one certificate.
- Key type and profile are part of the identity, which enables the dual
  RSA+ECDSA pattern for the same domains.

Worked examples:

| Container | Labels | Result |
|---|---|---|
| `web` | default cert `example.com,*.example.com` | 1 certificate, 1 target |
| `web` | default cert + `acmed.api.*` | 2 certificates, 2 targets |
| `web`, `api` | both request `api.example.com` | 1 certificate, 2 targets |
| `web` | `example.com` EC256 + `example.com` RSA2048 | 2 certificates (dual key), 2 targets |

## 6. Labels

Any running container with at least one `acmed.*` label is a target. Labels are
immutable; changing them requires recreating the container, which produces a
`start` event and is re-reconciled automatically.

### 6.1 Field groups

Bare (`acmed.<field>`) labels fall into two groups:

- **Certificate-defining** — `domains`, `path`, `manager-path`. These describe
  one specific certificate directory.
- **Container defaults** — `reload.cmd`, `reload.signal`, `ca`, `key-type`,
  `enable`. These apply to **every** certificate in the container unless
  overridden per certificate.

Named certificates use `acmed.<name>.<field>` for any of the above, where
`<name>` matches `[a-z0-9_-]+`. A named field overrides the corresponding
container default.

`manager-path` is deliberately **not** a container default: it is the
manager-side view of one specific target directory, so it belongs to that
certificate only.

`acmed.enable=false` on the bare labels opts the whole container out; a named
`acmed.<name>.enable=false` disables just that certificate.

### 6.2 Fields

| Label | Required | Meaning |
|---|---|---|
| `acmed.domains` | yes (per cert) | Comma-separated SAN list; first = CN. Wildcards `*.example.com` allowed. |
| `acmed.path` | yes (per cert) | Absolute directory **for this certificate** inside the target. |
| `acmed.reload.cmd` | one of | Shell command run in the target after files change. |
| `acmed.reload.signal` | one of | Signal sent to PID 1 (e.g. `SIGHUP`). Mutually exclusive with `cmd` at the same level. |
| `acmed.ca` | no | Ordered CA override, e.g. `gts,letsencrypt`. |
| `acmed.key-type` | no | `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, `rsa4096`. |
| `acmed.manager-path` | no | Explicit path inside the manager (bypasses auto-mapping). |
| `acmed.enable` | no | `false` opts out (container-wide or per certificate). |

### 6.3 Examples

One certificate:

```yaml
labels:
  acmed.domains: "example.com,*.example.com"
  acmed.path: /etc/nginx/certs/example.com
  acmed.reload.cmd: "nginx -s reload"
```

Several certificates with a shared reload default:

```yaml
labels:
  acmed.reload.cmd: "nginx -s reload"          # container default, inherited

  acmed.domains: "example.com,*.example.com"   # default certificate
  acmed.path: /etc/nginx/certs/example.com

  acmed.api.domains: "api.example.com"         # named certificate
  acmed.api.path: /etc/nginx/certs/api.example.com

  acmed.admin.domains: "admin.example.com"     # named certificate with override
  acmed.admin.path: /etc/nginx/certs/admin.example.com
  acmed.admin.reload.signal: SIGHUP
```

Dual-key (RSA + ECDSA) for one hostname:

```yaml
labels:
  acmed.domains: "example.com"
  acmed.path: /etc/nginx/certs/example.com/ec
  acmed.key-type: ec256

  acmed.rsa.domains: "example.com"
  acmed.rsa.path: /etc/nginx/certs/example.com/rsa
  acmed.rsa.key-type: rsa2048
  acmed.rsa.reload.signal: SIGHUP
```

### 6.4 Validation rules

- Domains: lowercased, IDNA/punycode-encoded, deduplicated, order preserved;
  wildcard only as the leftmost label.
- `path` must be absolute and unique per container; two certificates may not
  share a directory.
- `reload.cmd` and `reload.signal` are mutually exclusive at each level; a
  per-cert action replaces the inherited container default entirely.
- Invalid labels produce **per-container warnings**; a broken named certificate
  never invalidates the others, and never crashes the manager.
- A container that defines defaults but no certificates logs one warning and is
  otherwise ignored.

## 7. Configuration and secrets

`secrets/.env` (gitignored) is loaded via Compose `env_file`;
`secrets/.env.example` is committed. For any variable `FOO`, a `FOO_FILE` path
is read instead (Docker secrets), matching lego's own convention.

### ACME / CA

| Variable | Default | Notes |
|---|---|---|
| `ACME_CA_ORDER` | `letsencrypt` | Ordered candidate list, first = primary. |
| `ACME_DEFAULT_EMAIL` | — | Used when a CA has no email of its own. |
| `ACME_<NAME>_URL` | lego code if `<NAME>` is one | Code (`gts`, `letsencrypt`, `zerossl`, …) or raw directory URL. |
| `ACME_<NAME>_EMAIL` | default | Account contact. |
| `ACME_<NAME>_EAB_KID` | — | EAB key ID (GTS, ZeroSSL, Sectigo, …). |
| `ACME_<NAME>_EAB_HMAC` / `_FILE` | — | EAB HMAC. |
| `ACME_<NAME>_ACCOUNT_KEY_FILE` | — | Import an existing account key. |
| `ACME_STAGING` | `false` | Rewrite known production codes to staging counterparts; CAs without one are used as configured. |
| `ACME_KEY_TYPE` | `EC256` | Global default (per-cert override available). |
| `ACME_PREFERRED_CHAIN` | — | e.g. `ISRG Root X1`. |
| `ACME_PROFILE` | — | ACME certificate profile (e.g. `shortlived`). |
| `ACME_CA_CERT` / `_FILE` | — | Extra trust anchors (private CA, Pebble). |
| `ACME_CA_SERVER_NAME` | — | TLS SNI override for private ACME servers. |

### DNS-01

| Variable | Notes |
|---|---|
| `ACME_DNS_PROVIDER` | lego provider name (full registry), required. |
| `ACME_DNS_RESOLVERS` | Comma list, e.g. `1.1.1.1:53,8.8.8.8:53`. Wired via `dns01.SetDefaultClient`. |
| `ACME_DNS_DISABLE_AUTHORITATIVE_CHECK` | Test/split-horizon only. |
| `ACME_DNS_PROPAGATION_WAIT` | Fixed propagation wait. |
| provider credentials | `CF_DNS_API_TOKEN`, `AWS_*`, …; `_FILE` supported per provider. |

### Runtime

| Variable | Default | Notes |
|---|---|---|
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Unix or `tcp://`. |
| `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH` | — | TCP+TLS daemon. |
| `STATE_DIR` | `/data` | Accounts, certs, lock. |
| `CHECK_INTERVAL` | `12h` | ARI/renewal check cadence. |
| `RENEW_BEFORE` | auto | Override the lifetime-relative threshold. |
| `FAILURE_BACKOFF` | `1m,10m,100m,24h` | Retry schedule. |
| `MAX_CONCURRENT_ISSUANCE` | `2` | Bounded issuance parallelism. |
| `FILE_UID`, `FILE_GID` | writer's | Ownership of written files. |
| `FILE_MODE` / `KEY_MODE` | `0644` / `0640` | Permissions. |
| `LABEL_PREFIX` | `acmed` | Label namespace. |
| `LOG_LEVEL` | `info` | |
| `HTTP_ADDR` | `:8080` | `/healthz` status endpoint. |

Startup validation is fail-fast for global configuration (no usable CA, no DNS
provider, unreadable EAB secret). Per-container label problems are warnings.

## 8. CA selection and failover

- Every issuance/renewal walks the candidate order: the per-cert `acmed.ca`
  override if set, otherwise `ACME_CA_ORDER`. Unknown names are skipped with a
  warning; a certificate with no remaining candidates is skipped.
- The first CA that succeeds issues the certificate; `issuerCA` and `issuerURL`
  are recorded in `meta.json`.
- **Cache validity (D1):** a usable cached certificate is reused until it is
  due, regardless of candidate-order edits or staging ↔ production changes. The
  cache exists to protect ACME rate limits, so candidate changes never force
  reissuance, and a certificate issued by a previous candidate keeps serving
  until its renewal.
- **Renewal (D1):** ARI is queried from the recorded issuer. If the candidate
  being tried is the issuer — same CA name **and** the same directory URL — use
  `Renew` (key reuse, RFC 9773 `replaces`); otherwise `Obtain`, so the next
  certificate comes from the current candidate set.
- **Error classification (D2):**
  - *CA-side* (network, 5xx, `rateLimited`, badNonce): apply a per-CA cooldown
    (15m, doubling to a 6h cap, cleared on success).
  - *Validation* (`unauthorized`, CAA): per-certificate only — one broken domain
    never disables a CA for everyone. Failover still happens because CAA can
    block one CA and not another.
  - *Config/account* (bad EAB, invalid URL): skip the CA with a warning; it does
    not count as an attempt.
- Accounts are per CA and bound to the directory URL: key + registration under
  `accounts/<ca-name>/`. A stored registration is only reused for the URL it was
  created against, so staging and production accounts never cross. Account
  creation is serialized per CA to prevent duplicate registrations.
- One full order-walk per backoff cycle (D4). At the documented backoff a CA
  sees roughly three failed validations in the first hour, under Let's Encrypt's
  failed-validation limit.

## 9. Renewal policy

- Check every `CHECK_INTERVAL` (default 12h, per LE "at least twice a day"),
  plus on startup and on demand.
- **ARI first:** `GetRenewalInfo` → `ShouldRenewAt(now, willingToSleep)` (the
  RFC 9773 algorithm is lego's, not reimplemented); the drawn instant is
  selected once per window and honored — a nil draw waits for the next refresh;
  `RetryAfter` stretches the next ARI refresh interval; renew with
  `UseARICertID`.
- **Fallback (no ARI):** renew two thirds through the lifetime; halfway for
  certificates shorter than ten days. Optional `RENEW_BEFORE` override.
- **Backoff:** persisted per certificate, `1m → 10m → 100m → 24h`, gating every
  issuance attempt — including the first, forced reissues after a CA change,
  and renewals.
- **Cache-first:** issuance only when the certificate is absent, due, or
  explicitly forced. Cached certificates are shared across containers and
  restarts, whatever endpoint issued them.
- Rate-limit safeguards: persisted account keys, deduplication of identical
  requests, bounded concurrency, single-instance lock, GC of only expired and
  unreferenced certificates, and `--dry-run` never touching production.

## 10. Delivery

The manager writes through its **own** read-write mount of the same host path or
named volume that the target mounts. Mapping matches `Mount.Source` strings, so
bind mounts and named volumes both work and targets may mount `:ro`.

Algorithm:

1. Read `acmed.<cert>.path` (absolute directory inside the target).
2. Find the target mount with the longest `Destination` covering that path.
3. Translate the remainder onto the host `Source`.
4. Find the manager mount with the longest `Source` covering that host path and
   translate the remainder onto its `Destination`.
5. Write files atomically; then reload.

Rules:

- No covering mount, or the manager cannot see the source → the target is
  **misconfigured**, logged with an actionable message and surfaced in
  `/healthz`. There is no `docker cp` fallback.
- `acmed.manager-path` bypasses auto-mapping.
- `volume.subpath` mounts do not expose the subpath in inspect; require
  `manager-path` or avoid them.
- Mount directories, not single files.
- Recommended pattern for many containers: one external named volume
  (`acme-certs`) mounted by the manager once and by every target; certificates
  live in per-certificate subdirectories.

Files written per certificate directory (fixed names):

- `fullchain.pem` (leaf + chain), `cert.pem` (leaf), `chain.pem` (issuer),
  `privkey.pem`.

Write discipline: temp file in the same directory → `fsync` → `rename` →
`fsync` directory; unchanged content is skipped by byte comparison so mtimes do
not churn; leftover temp files are removed at startup.

## 11. Reload

- `acmed.reload.cmd` runs via `/bin/sh -c` inside the target with a 30s timeout;
  output is captured. Targets without a shell should use a signal.
- `acmed.reload.signal` is sent to PID 1. An unhandled `SIGHUP` terminates the
  container; this is documented.
- Neither configured → files are still written, a warning is logged, and the
  target reports `reload: none`.
- Reload runs only when file content actually changed.
- Failed reloads are retried on a later reconcile cycle and reported as
  `reload: failed` / `pending`; healthcheck stays green (liveness only) so
  orchestrators do not restart the manager over ACME or reload problems.

### Multi-certificate containers

- The effective reload action for a certificate is its per-cert
  `reload.cmd|signal` if set, otherwise the container default (§6.1).
- Within one reconcile cycle, deliveries to the same container are collected
  and each **distinct** reload action runs **once**, after all deliveries.
  Certificates sharing the action share its outcome. This prevents a container
  with several certificates from reloading its service once per certificate.
- Per-target retry state is preserved: a failed action stays pending for every
  target that needs it and is retried on a later cycle.

## 12. Storage

```
STATE_DIR/
  .lock                                  # flock: refuse a second instance
  accounts/<ca-name>/account.key         # 0600
  accounts/<ca-name>/account.json        # {directoryURL, registration}
  certs/<primary-domain>-<hash12>/
      fullchain.pem privkey.pem cert.pem chain.pem
      meta.json                          # domains, key type, profile, issuer name + URL,
                                         # certURL, obtainedAt, notBefore/notAfter,
                                         # ARI state, failure/backoff state
```

- Human-readable directory names for debugging.
- Atomic writes; temp files cleaned at startup.
- Non-expired certificates are never deleted; expired unreferenced ones are GC'd.
- Failure/backoff state is persisted even before any PEM exists, so a
  never-issued certificate keeps its backoff across restarts.

## 13. Watcher and lifecycle

- Initial full scan of running containers, then an `Events` stream filtered to
  container events (`start`, `die`, `destroy`, `rename`).
- Race-free startup: subscribe with `Since` = scan start (or subscribe first);
  reconciliation is idempotent and deduplicated by container ID.
- Reconnect on stream error plus a full resync; periodic resync (10m) as a
  safety net; due checks run on a 1-minute tick.
- Only running containers are managed. `die` removes delivery targets but keeps
  the certificate cache.
- The manager skips itself.
- Docker's `label` filter matches exact keys only, so the manager lists all
  running containers and parses labels locally.

## 14. Security

- Mounting `docker.sock` is root-equivalent; `:ro` does **not** restrict the
  API. Prefer a socket proxy allowing only containers/events/exec/kill, or a
  TCP+TLS daemon (`DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`).
- The manager runs as root by default for reliable writes into host-owned
  directories. Hardened mode: non-root user in the `docker` group plus
  `FILE_UID`/`FILE_GID`/`FILE_MODE`/`KEY_MODE`.
- SELinux (`:z`), rootless and Docker Desktop notes in the README.
- Secrets only via env/`_FILE`; never logged; redacted config dump.
- Single instance enforced with a flock in `STATE_DIR`.

## 15. Observability

- Structured `slog` logs including container name/ID, certificate, CA and event;
  no secrets.
- `/healthz` JSON: watcher state, self-detection, last resync, per-certificate
  (domains, candidates, issuer, notAfter, next attempt, last error) and
  per-target (delivered, reload state, error) detail, plus current warnings.
- The status document is assembled at the end of each reconcile cycle and
  served from memory, so `/healthz` never blocks behind an in-flight issuance.
- It always returns 200 while the process is alive: ACME and reload failures are
  reported in the body and must not trigger container restarts. `acmed
  healthcheck` checks liveness only.

## 16. CLI

- `acmed` / `acmed run` — daemon (default).
- `acmed check` — validate configuration and labels; print the redacted
  effective config with CA endpoints marked `PRODUCTION` / `STAGING` / `CUSTOM`.
- `acmed healthcheck` — liveness probe for the Docker healthcheck.
- `--once` — one scan/reconcile/renew cycle then exit.
- `--dry-run` — staging/custom endpoints only (production endpoints are
  refused), a separate state directory, no delivery and no reload. Safe on a
  production host.
- `--log-level`.

## 17. Packaging and deployment

- Multi-stage Dockerfile: `golang:1.26-alpine` build, distroless static final
  image (root by default), `/data` pre-created, healthcheck via the subcommand.
- A separate `test` build target adds a shell for the container end-to-end test;
  the product image stays distroless.
- Sample `compose.yml` with one external `acme-certs` volume shared by the
  manager and targets.
- `secrets/.env.example` documents every variable.

## 18. Testing and staging

- **Unit (offline):** label parsing/validation, container-default inheritance
  and overrides, IDNA normalization, config (multi-CA, staging rewrite,
  `_FILE`, redaction), scheduler lifetimes/backoff and ARI decision mapping,
  mount mapping,
  atomic writes, store/lock, and the reconciler with fake Docker/issuer
  (including the D1 staging→production rule, reload retry, reload coalescing,
  and per-target degradation).
- **Integration:** real DNS-01 issuance, account persistence, key-reusing
  renewal and CA failover against a local **Pebble + pebble-challtestsrv**
  stack. Deterministic, no external rate limits, never production.
- **End-to-end:** `test/e2e.sh` / `compose.test.yml` run Pebble + challtestsrv +
  acmed + nginx, assert delivery and reload, and smoke-test the distroless
  image.
- **Live staging (optional, manual):** real Let's Encrypt staging behind an
  explicit environment flag. Production is never used in tests.
- Staging behavior in the product: `ACME_STAGING` rewrites known production
  codes and leaves other CAs as configured; `--dry-run` refuses production
  endpoints, forces staging and never delivers; `check` labels endpoints.
  Documented rollout: `--dry-run` → staging for a day → production.

## 19. Design decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Cache reuse is issuer-agnostic; renewal is issuer-exact (name + URL) | The cache protects ACME rate limits, so candidate changes never force reissuance; renewal still only reuses the key in place on the exact endpoint that issued the cached certificate. |
| D2 | CA-wide cooldown only for CA-side errors | One broken domain must not disable a CA for every certificate. |
| D3 | DNS resolvers configured via `dns01.SetDefaultClient` | lego v5 removed the v4 challenge option; Docker's embedded DNS is a known flaky resolver. |
| D4 | One order-walk per backoff cycle | Failover helps with CA outages and CAA, without multiplying failed validations past the rate limit. |
| D5 | Healthcheck is liveness only | ACME/reload failures must not cause restart loops. |
| D6 | Reload is explicit; missing reload is loud | Silent stale-certificate serving is the worst failure mode. |
| D7 | Global file ownership/mode settings | Non-root targets need readable keys; one knob beats per-cert knobs. |
| D8 | Race-free event subscription | Containers started during the initial scan must not be missed. |
| D9 | Bind-mount-only delivery | A misconfigured container is visible and actionable rather than silently patched. |
| D10 | One or many certificates per container via named labels; certificates deduplicated by identity | One issuance per identity protects rate limits and makes certificate sharing free. |
| D11 | Bare reload/CA/key-type/enable labels are container defaults inherited by all certificates | Avoids repeating the same reload on every named certificate; per-cert overrides stay possible. |
| D12 | Reload actions are coalesced per container per cycle | N certificates renewing together reload the service once, not N times. |
| D13 | `manager-path` stays per certificate | It is the manager-side view of one specific directory and cannot be meaningfully shared. |

## 20. Implementation status

Implemented and verified:

- The certificate model of §5: a container may request one or many
  certificates via named labels, with per-certificate domains, directory, CA,
  key type and reload, deduplicated across containers (D10).
- Container defaults and per-certificate overrides for reload, CA, key type and
  enable (D11).
- Reload coalescing per container per reconcile cycle, with per-target retry
  state (D12).
- CA failover, per-CA accounts and cooldowns (one cached lego client per CA, so
  the directory is fetched once), ARI-first renewal delegated to lego with one
  draw per window, backoff-gated issuance on every path, GC of expired
  unreferenced certificates.
- Bind-mount delivery with automatic source mapping, atomic writes, reload
  retry, dry-run and staging behavior. The status endpoint serves a snapshot
  published each cycle and never blocks behind an issuance.
- Unit tests (including default inheritance, multi-certificate containers,
  coalescing, backoff gating, GC, cache reuse across candidate changes, and a
  non-blocking snapshot); Pebble integration tests (issuance, renewal, failover,
  concurrent issuance on the shared client); container end-to-end test;
  distroless image smoke test.

Verified commands:

```
go build ./...
go test ./...                 # unit
go test -race ./internal/...  # race
ACMED_INTEGRATION=1 go test ./internal/acmex/ -run TestPebble -v   # real ACME (Pebble)
bash test/e2e.sh              # container end-to-end
```

## 21. Trade-offs and deferred

- No atomic multi-file swap (microsecond rename window); applications re-read on
  reload.
- Bind-mount-only is stricter than `docker cp`; misconfiguration is visible.
- The manager defaults to root; hardened mode is documented.
- The full lego provider registry makes builds heavy (~200 modules); accepted
  for provider coverage.
- `reload.signal=SIGHUP` can kill a container whose PID 1 does not handle it.
- ARI is not universal; the lifetime fallback covers it.
- A certificate issued by a previous candidate may keep serving until its
  renewal; renewal then routes to the current candidate set (cache-first).
- `ACME_STAGING` no longer filters the CA order; only `--dry-run` refuses
  production endpoints.
- Deferred: revocation/import/export CLI, metrics, webhook notifications,
  per-certificate DNS provider override, CA stickiness, per-certificate ACME
  profiles.

## Appendix A — label reference

```
acmed.enable                  container-wide opt-out
acmed.domains                 default certificate: SAN list (first = CN)
acmed.path                    default certificate: absolute target directory
acmed.reload.cmd|signal       container default reload (per-cert overridable)
acmed.ca                      container default CA order override
acmed.key-type                container default key type
acmed.manager-path            default certificate: manager-side directory

acmed.<name>.domains          named certificate: SAN list
acmed.<name>.path             named certificate: absolute target directory
acmed.<name>.reload.cmd|signal named certificate reload override
acmed.<name>.ca               named certificate CA override
acmed.<name>.key-type         named certificate key type override
acmed.<name>.manager-path     named certificate manager-side directory
acmed.<name>.enable           named certificate opt-out
```

`<name>` matches `[a-z0-9_-]+`.

## Appendix B — on-disk certificate directory

```
certs/<primary-domain>-<hash12>/
  fullchain.pem   leaf + intermediates (what most servers load)
  cert.pem        leaf only
  chain.pem       issuer chain
  privkey.pem     private key
  meta.json       identity, issuer, validity, ARI and failure state
```
