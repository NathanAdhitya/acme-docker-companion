# acme-docker-companion

or shortened as `acmed` is a Docker sidecar that manages TLS certificates for many containers.
It reads Docker container labels, obtains and renews certificates with
[lego](https://github.com/go-acme/lego) using the DNS-01 challenge only, writes
the files into bind mounts, and reloads the target containers.

Note: This repository is currently not production ready. Most of the functionality was vibe-coded into existence.

See [`DESIGN.md`](DESIGN.md) for the design. See [`AGENTS.md`](AGENTS.md) for the
development rules.

## How it works

```
Docker labels ─► parse ─► reconcile ─► ACME DNS-01 (lego) ─► write files ─► reload
```

1. Add `acmed.*` labels to a running container. The container becomes a
   certificate target.
2. acmed computes the certificate identity from the domains, the key type, and
   the profile. Issues new if not found in cache.
3. acmed delivers the certificate through a bind mount that it shares with the
   target (path and named volumes are supported).
4. acmed reloads the target with a command or signal that you configure.

## Quick start

One possible pattern is one shared external volume for certificates:

```sh
docker volume create acme-certs
cp secrets/.env.example secrets/.env    # then edit it
docker compose up -d
```

`compose.yml` uses the published image
(`ghcr.io/nathanadhitya/acme-docker-companion:latest`, multi-arch amd64/arm64).
To build from source, replace the `image:` line with `build: .`.

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

The certificate appears in the volume at `example.com/`. The directory contains
`fullchain.pem`, `privkey.pem`, `cert.pem`, and `chain.pem`.

## Labels

| Label | Required | Meaning |
|---|---|---|
| `acmed.domains` | yes | Comma-separated SANs. The first name is the primary name. Wildcards are permitted. Certificates contain SANs only, and no CommonName. |
| `acmed.path` | yes | Absolute directory for this certificate inside the target. |
| `acmed.reload.cmd` | one of | Shell command that runs in the target after the files change. |
| `acmed.reload.signal` | one of | Signal sent to PID 1, for example `SIGHUP`. |
| `acmed.ca` | no | Ordered CA override, for example `gts,letsencrypt`. |
| `acmed.key-type` | no | `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, or `rsa4096`. |
| `acmed.manager-path` | no | Explicit path inside the manager. It skips automatic mapping. |
| `acmed.enable` | no | `false` disables the whole container, or one named certificate. |

You can request one certificate or many per container. Multiple certificates
use a name segment. The bare `reload`, `ca`, and `key-type` labels
are container defaults. Each certificate inherits a default unless the
certificate overrides it:

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

You can share certificates with the same domains, key type, and profile across
containers. acmed issues them once and delivers them everywhere. When several
certificates of one container change in the same cycle, acmed runs the reload
action once.

### Post-renewal reloads

Uses the `acmed.reload.cmd` or `acmed.reload.signal` label. A reload happens only
when the file content changes.

## Delivery and mount mapping

### How a path is resolved
To write a certificate, acmed translates `acmed.path` from the target container
into a path in the manager container. It uses the mounts that Docker reports for
each container.

1. Read `acmed.path`, for example `/app/cert`.
2. Find the target mount whose `Destination` covers that path. The longest
   prefix wins.
3. Remove the `Destination` prefix. Join the remainder onto the `Source` of that
   mount. The result is the host path.
4. Find the manager mount whose `Source` covers that host path. The longest
   prefix wins. Translate the remainder onto its `Destination`.
5. Write the files there. Then run reload signal/command.

Mount sources is matched with a string prefix comparison. The manager
learns its own mounts when it inspects its own container. The two sides do not
need identical container paths. The manager mount `Source` must be an ancestor
of the target mount `Source`, or an exact match.

### Host bind mounts

You can use host bind mounts. Set `acmed.path` to the path inside the target.
acmed resolves the host directory when it matches the host path that the target
mounted. This example works:

```yaml
services:
  acmed:
    image: ghcr.io/nathanadhitya/acme-docker-companion:latest
    volumes:
      - /opt/certs:/certs                 # manager sees the common parent
      - /var/run/docker.sock:/var/run/docker.sock:ro

  web:
    image: nginx:alpine
    volumes:
      - /opt/certs/project-name:/app/cert:ro
    labels:
      acmed.domains: "example.com"
      acmed.path: /app/cert               # directory inside the target
      acmed.reload.cmd: "nginx -s reload"
```

Resolution of the `web` target:

| Step | Value |
|---|---|
| `acmed.path` (inside target) | `/app/cert` |
| Target mount covering it | `Destination=/app/cert`, `Source=/opt/certs/project-name` |
| Host path | `/opt/certs/project-name` |
| Manager mount covering that | `Destination=/certs`, `Source=/opt/certs` |
| Written inside the manager | `/certs/project-name` |

The certificate goes to the host directory `/opt/certs/project-name`. The `web`
container sees it at `/app/cert`. The manager does not have to mount the exact
directory that the target mounts. A mount of a common parent (`/opt/certs`) is
sufficient, because acmed finds the longest covering source.

You can also mount the identical source in both containers. For example,
`/opt/certs/project-name:/certs` in the manager is an exact-source match.


### When mapping fails

If the target mounts no directory that covers `acmed.path`, or the manager
cannot see the host path (`Source`) that the target mounted, acmed reports the
target as `misconfigured`. It logs a clear message and shows the target in
`/healthz`. acmed copies no files, and it has no `docker cp` fallback.

Other rules:

- **The manager must see the target source, or a parent of the target source.**
  After acmed computes the target host path, the manager match is a string
  prefix comparison.
- **Relative compose paths are permitted.** Docker resolves `./certs` to an
  absolute host path before acmed inspects the container. Both containers see
  the same resolved string.
- **Symlinks and equivalent paths are not permitted.** If one service names
  `/opt/certs` and another service reaches the same directory through a symlink
  or a different path, the strings differ and mapping fails. A Docker Desktop VM
  path is an example of a different path. Use the same host path text on both
  sides.
- **Use named volumes to avoid SELinux `:z`.** Bind mounts can need it.
- **`volume.subpath` mounts do not show the subpath** in `docker inspect`.
  Automatic mapping cannot see the subpath. Set `acmed.manager-path`, or do not
  use `volume.subpath`.
- **Mount directories, not single files.**
- **Set `acmed.manager-path` to an exact directory inside the manager to skip
  automatic mapping.**

## Configuration

Configure acmed with environment variables. See
[`secrets/.env.example`](secrets/.env.example) for the full list. The most
important variables:

| Variable | Default | Notes |
|---|---|---|
| `ACME_CA_ORDER` | `letsencrypt` | Ordered CA list, with backups. |
| `ACME_STAGING` | `false` | Rewrites known CA codes to their staging endpoints. acmed uses other CAs as configured. |
| `ACME_KEY_TYPE` | `EC256` | Global default key type. |
| `ACME_PROFILE` | — | ACME certificate profile, for example `shortlived`. |
| `ACME_DNS_PROVIDER` | — | lego provider name. Required. |
| `ACME_DNS_RESOLVERS` | system | Recommended: `1.1.1.1:53,8.8.8.8:53`. |
| `STATE_DIR` | `/data` | Accounts, certificates, and the lock file. |
| `CHECK_INTERVAL` | `12h` | The interval between ARI and renewal checks. |
| `FAILURE_BACKOFF` | `1m,10m,100m,24h` | The retry schedule after a failure. |
| `FILE_UID` / `FILE_GID` | writer | Ownership of the delivered files. Set these for non-root targets. |
| `FILE_MODE` / `KEY_MODE` | `0644` / `0640` | The permissions of the delivered files. |

You can supply any variable `FOO` as a file instead by setting `FOO_FILE` to a
path (Docker secrets). lego DNS providers use the same `_FILE` convention for
their credentials.

### Some variables are read directly by lego

Not every variable belongs to acmed. acmed does not declare, rename, or validate
every setting. The DNS provider credentials and options are read directly by
lego from the process environment. acmed only passes the environment through.
Use the variable names that lego documents for the provider:

- `ACME_DNS_PROVIDER=cloudflare` reads `CF_DNS_API_TOKEN`.
- `ACME_DNS_PROVIDER=httpreq` reads `HTTPREQ_ENDPOINT`, `HTTPREQ_MODE`,
  `HTTPREQ_USERNAME`, and `HTTPREQ_PASSWORD`. It also reads the timeout and
  polling variables of the provider.

These variables are not in the acmed variable table or in `.env.example`,
because acmed does not own them. See the lego
[DNS provider documentation](https://go-acme.github.io/lego/dns/) for the exact
names. Each variable also accepts a `_FILE` suffix.

acmed reads all other variables itself:

| Setting | Owner | Names |
|---|---|---|
| CA order, key type, renewal timing, state directory | acmed | `ACME_*` |
| Per-CA URL, email, EAB, account key file | acmed | `ACME_<CA>_*` |
| DNS provider credentials and options | lego | The provider's own names, for example `CF_DNS_API_TOKEN` and `HTTPREQ_USERNAME`. |

### Multiple CAs (active/backup)

`ACME_CA_ORDER=googletrust,letsencrypt` tries GTS first. If GTS fails, acmed
tries Let's Encrypt. Per-CA settings use `ACME_<NAME>_*`, which covers the URL,
the email, and EAB. acmed reuses a cached certificate until it is due, whatever
endpoint issued it. A change to the candidate list or to staging mode does not
force reissuance. Renewal reuses the key in place only on the CA that issued the
cached certificate. In all other cases, acmed places a new order with the
current candidates.

### Renewal

acmed follows the Let's Encrypt integration guide. acmed consults **ARI** at
least twice a day and honors the suggested window. acmed draws the renewal
instant once per ARI refresh, not on every due check. Without ARI, renewal
happens two thirds through the certificate lifetime. For certificates shorter
than ten days, renewal happens halfway through the lifetime. After a failure,
acmed retries after `1m`, `10m`, `100m`, and then `24h`. acmed limits the issue
concurrency. It also removes duplicate requests.

## Security

- A mount of `docker.sock` is equivalent to root access. `:ro` does not restrict
  the API. Prefer a socket proxy that permits only containers, events, exec, and
  kill. A TCP and TLS daemon is also possible (`DOCKER_TLS_VERIFY`,
  `DOCKER_CERT_PATH`).
- The manager runs as root by default, so it can write into host-owned
  directories. For a hardened deployment, run the manager as a non-root user in
  the `docker` group. Set `FILE_UID`, `FILE_GID`, `FILE_MODE`, and `KEY_MODE`.
- SELinux users can need `:z` on bind mounts. Named volumes avoid this
  requirement.
- acmed reads secrets from the environment or from `_FILE` paths. acmed never
  logs secrets.

## Status

`GET /healthz` returns a JSON document. It contains the watcher state, the
issuer, expiry, and next attempt for each certificate, and the delivery and
reload state for each target. The endpoint always returns 200 while the process
is alive. It reports ACME and reload failures in the body. These failures never
restart the container. acmed publishes the document once per reconcile cycle,
so the endpoint never blocks behind an issuance in progress. The Docker
healthcheck runs `acmed healthcheck`, which checks liveness only.

## Development

```sh
make build          # build bin/acmed
make test           # unit tests (offline)
make race           # unit tests with the race detector
make integration    # real DNS-01 against a local Pebble ACME server (Docker)
make e2e            # full container stack: Pebble + acmed + nginx
make docker         # build the image
```

The integration tests and the end-to-end tests use **Pebble** and
**pebble-challtestsrv**, a local ACME server that is equivalent to a staging
server. They never contact a production CA. `DESIGN.md` documents optional
manual tests against real Let's Encrypt staging.

## Layout

| Path | Contents |
|---|---|
| `cmd/acmed` | CLI: `run` (default), `check`, `healthcheck`, `--once`, `--dry-run`. |
| `internal/config` | Environment and `_FILE` loading, multi-CA parsing, validation. |
| `internal/labels` | `acmed.*` label parsing and validation. |
| `internal/dockerx` | Docker API wrapper: list, inspect, events, exec, kill. |
| `internal/store` | Accounts, certificate cache, atomic writes, single-instance lock. |
| `internal/acmex` | lego wrapper: per-CA accounts, DNS-01, failover, ARI. |
| `internal/reconciler` | Desired state, issuance pipeline, delivery orchestration. |
| `internal/scheduler` | Pure force, lifetime, and backoff decisions. The ARI draw happens once per ARI refresh in the reconciler. |
| `internal/delivery` | Bind-mount path resolution and atomic file writes. |
| `internal/httpx` | `/healthz` status endpoint. |
