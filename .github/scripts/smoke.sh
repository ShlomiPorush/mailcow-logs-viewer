#!/usr/bin/env bash
# Boot the built image against a real PostgreSQL and prove the application
# actually works: health, SPA, static assets, Alembic head, and the manual
# job runner accepting every job the Status page lists, and a headless
# browser pass over every page (ui_smoke.py).
#
# Usage: smoke.sh <image tag>
# Runs in CI (ubuntu runner) and locally (Git Bash / WSL) against any image.
set -euo pipefail

IMAGE="${1:?usage: smoke.sh <image tag>}"
NET="mlv-smoke-net"
DB="mlv-smoke-db"
APP="mlv-smoke-app"
PORT="${SMOKE_PORT:-18080}"
BASE="http://localhost:${PORT}"
WORK="$(mktemp -d)"

fail() { echo "::error::$*"; echo "FAIL: $*"; exit 1; }
step() { echo; echo "==> $*"; }

cleanup() {
    echo
    echo "==> Container logs (${APP})"
    docker logs "${APP}" 2>&1 | tail -n 200 || true
    docker rm -f "${APP}" "${DB}" >/dev/null 2>&1 || true
    docker network rm "${NET}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

step "Start PostgreSQL"
docker network create "${NET}" >/dev/null
docker run -d --name "${DB}" --network "${NET}" \
    -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci -e POSTGRES_DB=ci \
    postgres:16-alpine >/dev/null
for i in $(seq 1 30); do
    if docker exec "${DB}" pg_isready -U ci -q 2>/dev/null; then break; fi
    sleep 1
    [ "$i" -eq 30 ] && fail "PostgreSQL did not become ready"
done

step "Start the application (${IMAGE})"
# mailcow is a placeholder: nothing in this smoke test needs a reachable
# mailcow, and every job must cope with an unreachable one without crashing.
docker run -d --name "${APP}" --network "${NET}" -p "${PORT}:8080" \
    -e MAILCOW_URL=https://mail.example.com \
    -e MAILCOW_API_KEY=ci-placeholder \
    -e POSTGRES_HOST="${DB}" -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci -e POSTGRES_DB=ci \
    -e SETTINGS_EDIT_VIA_UI_ENABLED=true \
    "${IMAGE}" >/dev/null

step "Wait for /api/health"
healthy=0
for i in $(seq 1 60); do
    if body=$(curl -fsS "${BASE}/api/health" 2>/dev/null); then
        if echo "${body}" | grep -q '"status": *"healthy"'; then healthy=1; break; fi
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${APP}" 2>/dev/null)" != "true" ]; then
        fail "application container exited during startup"
    fi
    sleep 2
done
[ "${healthy}" -eq 1 ] || fail "/api/health did not report healthy within 120s"
echo "health: ${body}"

step "SPA and static assets are served"
code=$(curl -s -o ${WORK}/index.html -w '%{http_code}' "${BASE}/")
[ "${code}" = "200" ] || fail "GET / returned ${code}"
grep -qi '<html' ${WORK}/index.html || fail "GET / did not return an HTML document"
for asset in app.js utils.js settings.js router.js; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/static/${asset}")
    [ "${code}" = "200" ] || fail "GET /static/${asset} returned ${code}"
done
for route in /dashboard /messages /settings; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${route}")
    [ "${code}" = "200" ] || fail "SPA route ${route} returned ${code}"
done

step "Alembic is at head"
current=$(docker exec "${APP}" sh -c 'cd /app && alembic current 2>/dev/null' | grep -oE '^[0-9a-f]{4,}' | head -n1 || true)
heads=$(docker exec "${APP}" sh -c 'cd /app && alembic heads 2>/dev/null' | grep -oE '^[0-9a-f]{4,}' | head -n1 || true)
[ -n "${heads}" ] || fail "could not read alembic heads inside the container"
[ "${current}" = "${heads}" ] || fail "alembic current (${current:-none}) != head (${heads})"
echo "alembic: ${current}"

step "No tracebacks during startup"
if docker logs "${APP}" 2>&1 | grep -q "Traceback (most recent call last)"; then
    fail "a traceback was logged during startup"
fi

step "Manual job runner accepts every job the Status page lists"
# Parsed inside the container so the host needs nothing beyond docker and curl
jobs=$(docker exec "${APP}" python3 -c 'import json,urllib.request; print(" ".join(json.load(urllib.request.urlopen("http://localhost:8080/api/settings/info"))["background_jobs"].keys()))')
[ -n "${jobs}" ] || fail "/api/settings/info returned no background_jobs"
bad=""
count=0
for job in ${jobs}; do
    count=$((count + 1))
    code=$(curl -s -o ${WORK}/job.json -w '%{http_code}' -X POST "${BASE}/api/settings/jobs/${job}/run")
    case "${code}" in
        200|409) echo "  ${job}: ${code}" ;;
        *) echo "  ${job}: ${code} $(cat ${WORK}/job.json)"; bad="${bad} ${job}(${code})" ;;
    esac
done
[ -z "${bad}" ] || fail "job runner rejected:${bad}"
echo "${count} jobs accepted"

step "Jobs finish without crashing the process"
# Wait until no job reports 'running' (each one retries the unreachable
# mailcow a few times first), capped so a hung job cannot stall CI forever.
running=""
for i in $(seq 1 90); do
    running=$(docker exec "${APP}" python3 -c 'import json,urllib.request; j=json.load(urllib.request.urlopen("http://localhost:8080/api/settings/info"))["background_jobs"]; print(" ".join(k for k,v in j.items() if v.get("status")=="running"))')
    [ -z "${running}" ] && break
    sleep 2
done
if [ -n "${running}" ]; then echo "still running after 180s: ${running}"; fi
[ "$(docker inspect -f '{{.State.Running}}' "${APP}")" = "true" ] || fail "application exited while running jobs"
curl -fsS "${BASE}/api/health" | grep -q '"status": *"healthy"' || fail "health degraded after running jobs"
# A job that fails because mailcow is unreachable is expected here; a job that
# raises TypeError/AttributeError/NameError is a programming error (#81).
if docker logs "${APP}" 2>&1 | grep -E "(TypeError|AttributeError|NameError|ImportError):" ; then
    fail "a job raised a programming error (see log lines above)"
fi

step "Browser pass over every page"
# Headless Chromium from the pinned Playwright image; the Python package is
# pinned to the same release so it uses the browsers the image ships.
PW_VERSION="1.56.0"
PW_IMAGE="mcr.microsoft.com/playwright/python:v${PW_VERSION}-noble"
SCRIPTS="$(cd "$(dirname "$0")" && (pwd -W 2>/dev/null || pwd))"
MSYS_NO_PATHCONV=1 docker run --rm --network "${NET}" --ipc=host \
    -v "${SCRIPTS}:/scripts:ro" "${PW_IMAGE}" \
    sh -c "pip install -q --disable-pip-version-check --root-user-action=ignore --break-system-packages playwright==${PW_VERSION} \
           && python /scripts/ui_smoke.py http://${APP}:8080" \
    || fail "browser pass found problems (see FAIL lines above)"

echo
echo "SMOKE OK"
