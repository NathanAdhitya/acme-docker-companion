#!/usr/bin/env bash
# End-to-end test: acmed issues a certificate from a local Pebble ACME server,
# delivers it into an nginx target through the shared volume, and reloads it.
#
# This is a staging-equivalent test and never contacts a production CA.
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE="docker compose -f compose.test.yml"
CERT_DIR="test/pebble"
MINICA="${CERT_DIR}/pebble.minica.pem"
VOLUME="acmed-e2e-certs"

cleanup() {
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Resetting the stack"
cleanup

echo "==> Starting Pebble, challtestsrv and nginx"
$COMPOSE up -d pebble challtestsrv nginx

echo "==> Waiting for Pebble"
for i in $(seq 1 60); do
  if curl -k -s -o /dev/null "https://127.0.0.1:14000/dir"; then
    break
  fi
  sleep 1
done
curl -k -s -o /dev/null "https://127.0.0.1:14000/dir" || { echo "Pebble did not start"; exit 1; }

echo "==> Copying Pebble's test CA"
mkdir -p "$CERT_DIR"
PEBBLE_ID="$($COMPOSE ps -q pebble)"
docker cp "${PEBBLE_ID}:/test/certs/pebble.minica.pem" "$MINICA"

echo "==> Starting acmed"
$COMPOSE up -d acmed

echo "==> Waiting for the certificate to be delivered"
ok=""
for i in $(seq 1 60); do
  if docker run --rm -v "${VOLUME}:/certs" alpine:3 \
      sh -c 'test -s /certs/nginx.test/fullchain.pem && test -s /certs/nginx.test/privkey.pem && test -s /certs/api.nginx.test/fullchain.pem && test -s /certs/api.nginx.test/privkey.pem'; then
    ok="yes"
    break
  fi
  sleep 2
done
if [ -z "$ok" ]; then
  echo "FAIL: certificate was not delivered"
  $COMPOSE logs acmed | tail -40
  exit 1
fi

echo "==> Verifying the issued certificate"
docker run --rm -v "${VOLUME}:/certs" alpine:3 \
  sh -c 'apk add --no-cache openssl >/dev/null 2>&1; openssl x509 -in /certs/nginx.test/fullchain.pem -noout -subject -issuer -dates'

echo "==> Verifying reload"
if $COMPOSE logs acmed | grep -q "delivered and reloaded"; then
  echo "reload recorded"
else
  echo "FAIL: no successful reload recorded"
  $COMPOSE logs acmed | tail -40
  exit 1
fi

echo "==> Verifying healthcheck"
$COMPOSE exec -T acmed /acmed healthcheck

echo "==> Verifying the product (distroless) image runs"
docker build -q -t acmed-e2e-distroless . >/dev/null
docker run --rm -e ACME_DNS_PROVIDER=exec -e ACME_CA_ORDER=letsencrypt acmed-e2e-distroless check >/dev/null

echo
echo "PASS: acmed issued, delivered and reloaded a certificate from Pebble"
