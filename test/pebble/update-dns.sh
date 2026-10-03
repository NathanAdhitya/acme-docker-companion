#!/usr/bin/env bash
# DNS-01 exec solver for pebble-challtestsrv, used by the integration test.
# lego invokes this as: <script> present|cleanup <fqdn> <value>
set -e

MGMT="${CHALLTESTSRV_MGMT:-http://localhost:8055}"

case "$1" in
  present)
    curl -s -X POST -d "{\"host\":\"$2\",\"value\":\"$3\"}" "$MGMT/set-txt" >/dev/null
    ;;
  cleanup)
    curl -s -X POST -d "{\"host\":\"$2\"}" "$MGMT/clear-txt" >/dev/null
    ;;
  *)
    echo "unknown action: $1" >&2
    exit 1
    ;;
esac
