#!/usr/bin/env bash
# Boot the demo image against PostgreSQL with nothing but database settings
# (the image carries everything else) and prove it runs cut off from the
# network: healthy, SPA served, and the network guard active in the live
# process.
#
# Usage: demo_smoke.sh <demo image tag>
set -euo pipefail

IMAGE="${1:?usage: demo_smoke.sh <demo image tag>}"
NET="mlv-demo-smoke-net"
DB="mlv-demo-smoke-db"
APP="mlv-demo-smoke-app"
PORT="${SMOKE_PORT:-18090}"
BASE="http://localhost:${PORT}"

fail() { echo "::error::$*"; echo "FAIL: $*"; exit 1; }
step() { echo; echo "==> $*"; }

cleanup() {
    echo
    echo "==> Container logs (${APP})"
    docker logs "${APP}" 2>&1 | tail -n 200 || true
    docker rm -f "${APP}" "${DB}" >/dev/null 2>&1 || true
    docker network rm "${NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Start PostgreSQL"
docker network create "${NET}" >/dev/null
docker run -d --name "${DB}" --network "${NET}" \
    -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
    postgres:16-alpine >/dev/null
for i in $(seq 1 30); do
    if docker exec "${DB}" pg_isready -U demo -q 2>/dev/null; then break; fi
    sleep 1
    [ "$i" -eq 30 ] && fail "PostgreSQL did not become ready"
done

step "Start the demo application (${IMAGE})"
docker run -d --name "${APP}" --network "${NET}" -p "${PORT}:8080" \
    -e POSTGRES_HOST="${DB}" \
    -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
    "${IMAGE}" >/dev/null

step "Wait for /api/health"
healthy=0
for i in $(seq 1 60); do
    if body=$(curl -fsS "${BASE}/api/health" 2>/dev/null); then
        if echo "${body}" | grep -q '"status": *"healthy"'; then healthy=1; break; fi
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${APP}" 2>/dev/null)" != "true" ]; then
        fail "demo container exited during startup"
    fi
    sleep 2
done
[ "${healthy}" -eq 1 ] || fail "/api/health did not report healthy within 120s"
echo "health: ${body}"

step "SPA is served without a login"
for route in / /dashboard /messages /settings; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${route}")
    [ "${code}" = "200" ] || fail "GET ${route} returned ${code}"
done

step "The demo runs on the asyncio loop with the network guard installed"
logs=$(docker logs "${APP}" 2>&1)
echo "${logs}" | grep -q "\[DEMO\] Outbound network disabled" || fail "network guard was not installed"
echo "${logs}" | grep -q "\[DEMO\] Demo mode active" || fail "demo entry point did not load"
docker exec "${APP}" sh -c 'cat /proc/1/cmdline | tr "\0" " "' | grep -q -- "--loop asyncio" \
    || fail "uvicorn is not running on the asyncio loop (uvloop bypasses the guard)"

step "No tracebacks during startup"
if echo "${logs}" | grep -q "Traceback (most recent call last)"; then
    fail "a traceback was logged during startup"
fi

echo
echo "DEMO SMOKE OK"
