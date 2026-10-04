# acme-docker-companion
(or abbreviated as acmed).  
Note: This repository is currently not production ready. Most of the functionality was vibe-coded into existence.

`acmed` is a single-purpose Docker sidecar that keeps TLS certificates fresh
for **many** containers. It watches the Docker socket for container labels,
obtains and renews certificates with [lego](https://github.com/go-acme/lego)
using **DNS-01 only**, writes them into bind-mounted directories, and reloads
the containers.

- **Simple**: one binary, one `.env`, a few labels.
- **Reliable**: cache-first (never burns ACME rate limits), ARI-aware renewal,
  ordered active/backup CAs, atomic writes, explicit reloads.
- **Safe by default**: atomic writes, explicit reloads, and a cache that never
  wastes ACME rate limits.

See [`DESIGN.md`](DESIGN.md) for the full design and [`AGENTS.md`](AGENTS.md) for
the working rules.

## How it works

```
Docker labels ─► parse ─► reconcile ─► ACME DNS-01 (lego) ─► write files ─► reload
```

1. Any running container with `acmed.*` labels is a certificate target.
2. acmed derives the certificate identity from the domains, key type and
   profile, and reuses a cached certificate whenever one exists — issuing only
   when it is missing or due for renewal. Candidate or staging changes never
   force reissuance.
3. Certificates are delivered through a bind mount shared with the target.
4. The target is reloaded with the command or signal you configure.

## Quick start

The recommended pattern is **one shared external volume** for certificates:

```sh
docker volume create acme-certs
cp secrets/.env.example secrets/.env    # then edit it
docker compose up -d
```

`compose.yml` pulls the published image
(`ghcr.io/nathanadhitya/acme-docker-companion:latest`, multi-arch
amd64/arm64). To build from source instead, swap the `image:` line for
`build: .`.

Minimal `.env`:

```env
ACME_CA_ORDER=letsencrypt
ACME_DEFAULT_EMAIL=admin@example.com
ACME_DNS_PROVIDER=cloudflare
CF_DNS_API_TOKEN=...
ACME_DNS_RESOLVERS=1.1.1.1:53,8.8.8.8:53
```

Then label a target and mount the shared volume:

```yaml
services:
  web:
    image: nginx:alpine
    volumes:
      - acme-certs:/etc/nginx/certs:ro
    labels:
      acmed.domains: "example.com,*.example.com"
      acmed.path: /etc/nginx/certs/example.com
      acmed.reload.cmd: "nginx -s reload"
```

The certificate appears in the volume at `example.com/` with
`fullchain.pem`, `privkey.pem`, `cert.pem` and `chain.pem`.

## Labels

| Label | Required | Meaning |
|---|---|---|
| `acmed.domains` | yes | Comma-separated SANs; order preserved, the first is the primary name. Wildcards allowed. Certificates are SAN-only (no CommonName). |
| `acmed.path` | yes | Absolute directory **for this certificate** inside the target. |
| `acmed.reload.cmd` | one of | Shell command run in the target after files change. |
| `acmed.reload.signal` | one of | Signal sent to PID 1 (e.g. `SIGHUP`). |
| `acmed.ca` | no | Ordered CA override, e.g. `gts,letsencrypt`. |
| `acmed.key-type` | no | `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, `rsa4096`. |
| `acmed.manager-path` | no | Explicit path inside the manager (skips auto-mapping). |
| `acmed.enable` | no | `false` opts out (whole container, or one named certificate). |

A container may request **one or many** certificates. Multiple certificates use
a name segment, and bare `reload`/`ca`/`key-type` labels act as container-wide
defaults that each certificate inherits unless it overrides them:

```yaml
labels:
  acmed.reload.cmd: "nginx -s reload"          # container default

  acmed.domains: "example.com,*.example.com"   # default certificate
  acmed.path: /etc/nginx/certs/example.com

  acmed.web.domains: "api.example.com"         # named certificate, inherits reload
  acmed.web.path: /etc/nginx/certs/api.example.com
  acmed.web.ca: gts,letsencrypt

  acmed.admin.domains: "admin.example.com"     # named certificate with its own reload
  acmed.admin.path: /etc/nginx/certs/admin.example.com
  acmed.admin.reload.signal: SIGHUP
```

Certificates with the same domains, key type and profile are shared across
containers: they are issued once and delivered everywhere. When several
certificates of one container change in the same cycle, its reload action runs
once.

### Reloads are explicit

acmed never guesses a reload mechanism. Without `acmed.reload.cmd` or
`acmed.reload.signal` it still writes the files, logs a warning, and reports
`reload: none` in the status endpoint. Reloads happen only when file content
actually changed.

## Delivery and mount mapping

acmed writes through its **own** read-write mount of the same host path or
named volume that the target mounts. It matches mounts by their Docker
`Source`, so named volumes and bind mounts both work, and targets may mount
`:ro`.

If mapping fails (the target mounts nothing covering `acmed.path`, or the
manager cannot see the host path) the target is reported as `misconfigured` and
no files are copied — there is no silent `docker cp` fallback. Set
`acmed.manager-path` to bypass mapping.

## Configuration

Everything is environment based; see [`secrets/.env.example`](secrets/.env.example)
for the full list. Highlights:

| Variable | Default | Notes |
|---|---|---|
| `ACME_CA_ORDER` | `letsencrypt` | Ordered active/backup CA chain. |
| `ACME_STAGING` | `false` | Rewrite known CA codes to their staging endpoints; other CAs are used as configured. |
| `ACME_KEY_TYPE` | `EC256` | Global default key type. |
| `ACME_PROFILE` | — | ACME certificate profile (e.g. `shortlived`). |
| `ACME_DNS_PROVIDER` | — | lego provider name (required). |
| `ACME_DNS_RESOLVERS` | system | Recommended: `1.1.1.1:53,8.8.8.8:53`. |
| `STATE_DIR` | `/data` | Accounts, certificates, lock file. |
| `CHECK_INTERVAL` | `12h` | ARI/renewal check cadence. |
| `FAILURE_BACKOFF` | `1m,10m,100m,24h` | Retry schedule after failures. |
| `FILE_UID` / `FILE_GID` | writer | Ownership of delivered files (set for non-root targets). |
| `FILE_MODE` / `KEY_MODE` | `0644` / `0640` | Delivered file permissions. |

For any variable `FOO`, a `FOO_FILE` path is read instead (Docker secrets),
and most lego DNS providers support the same convention for their credentials.

### Multiple CAs (active/backup)

`ACME_CA_ORDER=googletrust,letsencrypt` tries GTS first and falls back to
Let's Encrypt. Per-CA settings use `ACME_<NAME>_*` (URL, email, EAB). A cached
certificate is reused until it is due, whatever endpoint issued it; changing
the candidate list or staging mode never forces reissuance. Renewal reuses the
key in place only on the CA that issued the cached certificate, and otherwise
places a fresh order with the current candidates.

### Renewal

Renewal follows the Let's Encrypt integration guide: **ARI** is consulted at
least twice a day and its suggested window is honored (the renewal instant is
drawn once per ARI refresh, not on every due tick); without ARI, renewal
happens two thirds through the lifetime (halfway for certificates shorter than
ten days). Failures back off
`1m → 10m → 100m → 24h`. Issuance concurrency is bounded and identical requests
are deduplicated.

## Security

- Mounting `docker.sock` is root-equivalent; `:ro` does **not** restrict the
  API. Prefer a socket proxy that allows only containers/events/exec/kill, or a
  TCP+TLS daemon (`DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`).
- The manager runs as root by default so it can write into host-owned
  directories. For a hardened deployment run it as a non-root user in the
  `docker` group and set `FILE_UID`/`FILE_GID`/`FILE_MODE`/`KEY_MODE`.
- SELinux users may need `:z` on bind mounts; named volumes avoid this.
- Secrets are read from the environment or `_FILE` paths and are never logged.

## Status

`GET /healthz` returns a JSON document with watcher state, per-certificate
issuer/expiry/next attempt, and per-target delivery/reload state. It always
returns 200 while the process is alive; ACME and reload failures are reported
in the body and never trigger container restarts. The document is published
once per reconcile cycle, so the endpoint never blocks behind an in-flight
issuance. The Docker healthcheck uses `acmed healthcheck`, which only checks
liveness.

## Development

```sh
make build          # build bin/acmed
make test           # unit tests (offline)
make race           # unit tests with the race detector
make integration    # real DNS-01 against a local Pebble ACME server (Docker)
make e2e            # full container stack: Pebble + acmed + nginx
make docker         # build the image
```

The integration and end-to-end tests use **Pebble** and
**pebble-challtestsrv** — a local, staging-equivalent ACME server. They never
contact a production CA. Optional manual testing against real Let's Encrypt
staging is documented in `DESIGN.md`.

## Layout

| Path | Contents |
|---|---|
| `cmd/acmed` | CLI: `run` (default), `check`, `healthcheck`, `--once`, `--dry-run`. |
| `internal/config` | Environment + `_FILE` loading, multi-CA parsing, validation. |
| `internal/labels` | `acmed.*` label parsing and validation. |
| `internal/dockerx` | Docker API wrapper (list/inspect/events/exec/kill). |
| `internal/store` | Accounts, certificate cache, atomic writes, single-instance lock. |
| `internal/acmex` | lego wrapper: per-CA accounts, DNS-01, failover, ARI. |
| `internal/reconciler` | Desired state, issuance pipeline, delivery orchestration. |
| `internal/scheduler` | Pure force/lifetime/backoff decisions; the ARI draw happens once per ARI refresh in the reconciler. |
| `internal/delivery` | Bind-mount path resolution and atomic file writes. |
| `internal/httpx` | `/healthz` status endpoint. |
