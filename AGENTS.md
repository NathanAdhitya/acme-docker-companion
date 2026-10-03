# AGENTS.md — working rules for `acme-docker-companion`

Read `DESIGN.md` for the full design. This file is the short version: what the project
is, what must never break, and how to work on it.

## What this is

`acmed` is a single-purpose Docker sidecar: it watches a Docker socket for container
labels, obtains/renews TLS certificates via lego (DNS-01 only), writes them into
bind-mounted directories, and reloads the containers. One binary, one `.env`, a few
labels. Optimize for **simplicity and reliability**, not features.

## Hard invariants (do not violate)

1. **DNS-01 only.** HTTP-01 / TLS-ALPN-01 solvers are removed from the lego client.
2. **Never issue when a usable cached cert exists.** Issuance only when: absent,
   renewal due, or explicit force. Candidate changes (CA order, staging ↔
   production) never force reissuance; this protects ACME rate limits.
3. **Cache reuse is issuer-agnostic; renewal is issuer-exact.** A cached cert keeps
   serving until it is due, whatever endpoint issued it. In-place `Renew` only when
   the stored CA name and directory URL match the candidate being tried; otherwise
   `Obtain` from the current candidate set.
4. **No `docker cp`.** Delivery is bind mounts only; a container whose path cannot be
   mapped is marked misconfigured, not patched.
5. **Reload is explicit.** Never invent a default signal/command. No reload label →
   write files, WARN, show `reload: none` in status.
6. **Never log secrets.** Provider tokens, EAB HMACs, account keys stay out of logs;
   config dumps are redacted.
7. **Per-container label errors are warnings**, never crashes; global config errors
   fail fast at startup.
8. **One instance.** Hold the `STATE_DIR/.lock` flock; refuse to start otherwise.
9. **Tests never touch production ACME.** Pebble/challtestsrv in CI; real LE staging
   only behind `E2E_LETSENCRYPT_STAGING=1`.
10. **Healthcheck is liveness only.** ACME/reload failures must not trigger container
    restarts; report them in `/healthz` JSON. The status document is published once
    per reconcile cycle, so the endpoint never blocks behind in-flight ACME work.

## Toolchain

- Go **1.26+** (lego v5 requires it).
- `github.com/go-acme/lego/v5` — pin the version; v5 API differs from v4 docs.
- `github.com/moby/moby/client` (+ `github.com/moby/moby/api`) — current Docker SDK.
  Do not use `github.com/docker/docker/client` (stale, vulnerable).
- Docker + Compose for integration tests. Go 1.26 available locally or build in the
  container.

## Commands

```sh
go build ./...
go vet ./...
go test ./... -race                 # unit tests, offline
golangci-lint run                   # if available
docker build -t acmed:dev .         # image
ACMED_INTEGRATION=1 go test ./internal/acmex/ -run TestPebble -v   # real DNS-01 vs Pebble
bash test/e2e.sh                    # full container stack: Pebble + acmed + nginx
```

## Layout

| Path | Contents |
|---|---|
| `cmd/acmed/` | CLI: `run` (default), `check`, `healthcheck`, `--once`, `--dry-run` |
| `internal/config/` | env + `_FILE`, multi-CA parsing, validation, redacted dump |
| `internal/labels/` | `acmed.*` label parsing → cert requests; container defaults + per-cert overrides; validation |
| `internal/dockerx/` | moby client wrapper: list/inspect/events/exec/kill, self-mount map |
| `internal/store/` | account + cert cache, atomic writes, `meta.json`, flock |
| `internal/acmex/` | lego wrapper: CA clients, accounts/EAB, obtain/renew, ARI |
| `internal/reconciler/` | demand set, dedupe, single-flight, delivery orchestration, reload coalescing |
| `internal/scheduler/` | pure force/lifetime/backoff decisions; the ARI draw happens once per window in the reconciler |
| `internal/delivery/` | mount-path resolution + atomic file writes |
| `internal/reload/` | exec command / signal with timeout + retries |
| `internal/httpx/` | `/healthz` JSON |
| `test/` | integration + e2e fixtures (Pebble, challtestsrv, nginx) |

## Conventions

- Wrap errors with context (`fmt.Errorf("...: %w", err)`); no panics in runtime paths.
- `log/slog` for structured logs; include container name/ID, cert, CA.
- Pass `context.Context` through Docker/ACME calls; honor cancellation on shutdown.
- Keep scheduler/reconciler logic pure and clock-injectable so it is unit-testable.
- The reconciler is single-writer: live state is mutated only on the main loop
  (`resync`/`process`); `Snapshot` serves an immutable status published at the end of
  each cycle. Do not reintroduce per-state locks without a second writer.
- All Docker and ACME access behind interfaces; fakes for tests.
- Atomic file writes: temp in same dir → `fsync` → `rename` → `fsync` dir; skip
  unchanged content by hash.
- Domain normalization: lowercase, punycode, dedupe, preserve order (first = CN).

## Upstream API gotchas (verified 2026-10)

- lego v5 is **context-first**: `Obtain(ctx, req)`, `Renew(ctx, res, opts)`,
  `GetRenewalInfo(ctx, leaf)`.
- The lego **library** is `github.com/go-acme/lego/v5/lego`; the module root is the
  CLI `main` package. `Client.Certificate` / `.Registration` / `.Challenge` are the
  entry points; `Certifier` lives in `.../certificate`, `Registrar`/`User` in
  `.../registration`.
- `certcrypto.PEMEncode` accepts `*ecdsa.PrivateKey`, `*rsa.PrivateKey`,
  `*x509.CertificateRequest` and `certcrypto.DERCertificateBytes` — **not**
  `*x509.Certificate`. Wrap cert DER: `PEMEncode(DERCertificateBytes(cert.Raw))`.
- Resolvers: **no `dns01.AddRecursiveNameservers` in v5.** Use
  `dns01.NewOptions()` + `dns01.NewClient(opts)` + `dns01.SetDefaultClient(c)`;
  `Options{RecursiveNameservers, Timeout, TCPOnly, NetworkStack}`.
- CA URLs: `lego.GetDirectoryURL(code)` (`letsencrypt`, `letsencrypt-staging`,
  `googletrust`, `googletrust-staging`, `zerossl`, …).
- EAB: `RegisterWithExternalAccountBinding(ctx, RegisterEABOptions{Kid, HmacEncoded})`;
  ZeroSSL: `RegisterWithZeroSSL(ctx, registrar, email)`.
- `Renew` reuses the key only if `Resource.PrivateKey` is set; renew with the recorded
  issuer uses `RenewOptions.UseARICertID`; a different candidate uses `Obtain`.
- ARI: `certificate.RenewalInfo.ShouldRenewAt(now, willingToSleep)` implements
  the RFC 9773 window and jitter; use it rather than reimplementing the window
  math. Draw it once per fetched window and keep the returned instant —
  re-drawing on every tick collapses the jitter to the start of the window.
  `api.ErrNoARI` means fall back to the lifetime rule (two thirds; half
  for <10 days). `RetryAfter` is the minimum interval before the next ARI
  query.
- lego clients are safe for concurrent use; acmed caches one per CA and reuses
  it for issuance and ARI. Registering through that client (`cli.Registration`)
  sets its account URL, so a separate registration client is unnecessary.
- Docker SDK results are structs: `ContainerListResult.Items`,
  `ContainerInspectResult.Container` (`.Mounts`, `.Config.Labels`),
  `EventsResult{Messages, Err}`, `ExecCreateOptions{Cmd, AttachStdout, AttachStderr}`,
  `ContainerKillOptions{Signal}`. `client.New(client.FromEnv)` negotiates the API
  version automatically.
- Docker's embedded DNS is `127.0.0.11`; set `ACME_DNS_RESOLVERS` explicitly when
  propagation checks misbehave.

## Operational gotchas

- Target mounts can be `:ro`; the manager writes via its own RW mount of the same
  source. Mapping compares `Mount.Source` strings — works for bind mounts and named
  volumes on Linux/macOS.
- `volume.subpath` mounts don't expose the subpath in inspect; require
  `acmed.manager-path` or avoid them.
- File ownership matters: non-root targets need `FILE_UID`/`FILE_GID`/modes set;
  mention SELinux `:z` and rootless in docs.
- `reload.signal` is sent to PID 1; an unhandled SIGHUP kills the container.
- Docker labels are immutable: changes require container recreation, which produces a
  `start` event and re-reconciles automatically.
- Startup must subscribe with `Since` = scan start (or subscribe first) to avoid
  missing containers started during the initial scan.

## Workflow expectations

- Implement design changes from `DESIGN.md`; the certificate model (§5) and the
  label rules (§6) are the parts most likely to be touched. Keep the Pebble
  integration test passing before layering anything on top.
- Any design change: update `DESIGN.md` (and this file if invariants/conventions change)
  in the same change.
- New behavior needs tests: unit for pure logic (label inheritance, coalescing,
  scheduling), Pebble integration for anything that talks ACME/Docker.
- Keep the default path simple: single CA, single DNS provider, shared named
  volume, one label set per certificate. Multi-CA, multi-certificate containers,
  per-cert overrides, and escape hatches are opt-in.
- When in doubt, prefer the option that cannot consume ACME rate limits or serve a
  wrong certificate.
