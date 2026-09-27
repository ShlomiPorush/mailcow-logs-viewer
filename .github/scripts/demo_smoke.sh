#!/usr/bin/env bash
# Boot the demo image against PostgreSQL with nothing but database settings
# (the image carries everything else) and prove it runs cut off from the
# network: healthy, SPA served, the network guard active in the live process,
# pages fed by the fictional mailcow and internet, a week of history on every
# page, writes that stick, every background job run, not one outbound
# attempt left for the guard, and a reset that drops visitor changes.
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

# Extra arguments are passed to docker run (-e ...)
start_app() {
    docker run -d --name "${APP}" --network "${NET}" -p "${PORT}:8080" \
        -e POSTGRES_HOST="${DB}" \
        -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
        "$@" "${IMAGE}" >/dev/null
}

wait_healthy() {
    local healthy=0
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
}

step "Start the demo application (${IMAGE})"
start_app

step "Wait for /api/health (the demo seeds a week of history first)"
wait_healthy

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

step "mailcow answers from the fictional server"
# Evaluated inside the container so the host needs nothing beyond docker and curl.
# Usage: check <path> <python expression over `d`> <description>
check() {
    docker exec "${APP}" python3 -c "
import json, sys, urllib.request
d = json.load(urllib.request.urlopen('http://localhost:8080$1'))
sys.exit(0 if ($2) else 1)" || fail "$3"
    echo "  ok: $3"
}
check /api/status/mailcow-connection 'd["connected"] is True' "mailcow connection test succeeds"
check /api/status/mailcow-info 'd["domains"]["active"] == 3 and d["mailboxes"]["total"] >= 10' "domains and mailboxes are listed"
check /api/status/containers 'len(json.dumps(d)) > 200 and "postfix-mailcow" in json.dumps(d)' "containers are reported"
check /api/queue 'd["total"] >= 4' "the mail queue has entries"
check /api/quarantine 'd["total"] >= 5' "the quarantine has entries"
check /api/fail2ban 'len(d["active_bans"]) >= 2' "fail2ban shows bans"
check /api/rspamd/maps/bad_words.map '"prize" in json.dumps(d)' "Rspamd maps are readable"

step "Every page has a week of fictional history"
check /api/stats/dashboard 'd["messages"]["7d"] >= 400 and d["auth_failures"]["7d"] > 0' "dashboard counts a week of mail and attacks"
check /api/messages/facets 'all(d["direction"][k] > 0 for k in ("inbound", "outbound", "internal")) and d["status"]["bounced"] > 0' "messages in every direction and outcome"
check /api/dmarc/domains 'd["total"] == 2 and all(x["report_count"] > 0 for x in d["domains"])' "DMARC reports for both domains"
check /api/suppressions/stats 'd["active"] > 0' "bounces became suppressions"
check /api/mailbox-stats/summary 'd["total_messages"] > 0' "mailbox statistics"
check /api/blacklist/summary 'd["listed_count"] == 1' "blocklist results"
check /api/security-alerts 'len(d["alerts"]) >= 1' "a security alert was raised"

step "The rest of the internet answers from fakes"
code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/docs/Domains")
[ "${code}" = "200" ] || fail "help document was not served (${code})"
echo "  ok: help documents are served from the image"
dns=$(curl -fsS -X POST "${BASE}/api/domains/example.com/check-dns" || true)
echo "${dns}" | grep -q '"dmarc"' || fail "the DNS check for example.com did not return results: ${dns}"
echo "  ok: domain DNS checks answer"

step "A write action changes what the demo shows"
before=$(docker exec "${APP}" python3 -c 'import json,urllib.request; print(json.load(urllib.request.urlopen("http://localhost:8080/api/quarantine"))["data"][0]["id"])')
result=$(curl -fsS -X POST -H 'Content-Type: application/json' -d "{\"items\":[\"${before}\"]}" "${BASE}/api/quarantine/release")
echo "${result}" | grep -q '"status": *"success"' || fail "quarantine release did not succeed: ${result}"
check /api/quarantine "all(str(i['id']) != '${before}' for i in d['data'])" "the released item left the quarantine"

step "Every background job runs against the fictional server"
jobs=$(docker exec "${APP}" python3 -c 'import json,urllib.request; print(" ".join(json.load(urllib.request.urlopen("http://localhost:8080/api/settings/info"))["background_jobs"].keys()))')
[ -n "${jobs}" ] || fail "/api/settings/info returned no background_jobs"
for job in ${jobs}; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/settings/jobs/${job}/run")
    case "${code}" in 200|409) ;; *) fail "job runner rejected ${job} (${code})" ;; esac
done
running=""
for i in $(seq 1 90); do
    running=$(docker exec "${APP}" python3 -c 'import json,urllib.request; j=json.load(urllib.request.urlopen("http://localhost:8080/api/settings/info"))["background_jobs"]; print(" ".join(k for k,v in j.items() if v.get("status")=="running"))')
    [ -z "${running}" ] && break
    sleep 2
done
[ -z "${running}" ] || echo "  still running after 180s: ${running}"
[ "$(docker inspect -f '{{.State.Running}}' "${APP}")" = "true" ] || fail "the demo exited while running jobs"
if docker logs "${APP}" 2>&1 | grep -E "(TypeError|AttributeError|NameError|KeyError|ImportError):"; then
    fail "a job raised a programming error against the fictional server (see above)"
fi

step "Every outbound path was answered by a fake"
# The guard is the last line of defence: in a correct demo nothing reaches it.
logs=$(docker logs "${APP}" 2>&1)
if echo "${logs}" | grep -q "Fake mailcow has no answer"; then
    echo "${logs}" | grep "Fake mailcow has no answer" | sort | uniq -c
    fail "the application called a mailcow endpoint the fake server does not answer"
fi
if echo "${logs}" | grep -qE "\[DEMO\] (Blocked outbound connection|No fake answer)"; then
    echo "${logs}" | grep -E "\[DEMO\] (Blocked outbound connection|No fake answer)" | sort | uniq -c
    fail "an outbound request was not answered by a fake (see above)"
fi

step "No tracebacks during startup"
if echo "${logs}" | grep -q "Traceback (most recent call last)"; then
    fail "a traceback was logged during startup"
fi

step "The nightly reset drops visitor changes and rebuilds the demo"
# The same reset as at 00:00, brought forward so the test does not wait for midnight
docker rm -f "${APP}" >/dev/null
start_app -e DEMO_RESET_AFTER_SECONDS=45
wait_healthy
count() { docker exec "${APP}" python3 -c 'import json,urllib.request; print(json.load(urllib.request.urlopen("http://localhost:8080/api/quarantine"))["total"])'; }
fresh=$(count)
first=$(docker exec "${APP}" python3 -c 'import json,urllib.request; print(json.load(urllib.request.urlopen("http://localhost:8080/api/quarantine"))["data"][0]["id"])')
curl -fsS -X POST -H 'Content-Type: application/json' -d "{\"items\":[\"${first}\"]}" "${BASE}/api/quarantine/release" >/dev/null
[ "$(count)" -eq $((fresh - 1)) ] || fail "the visitor change did not show before the reset"
for i in $(seq 1 60); do
    [ "$(docker logs "${APP}" 2>&1 | grep -c "\[DEMO\] Demo ready")" -ge 2 ] && break
    sleep 3
done
docker logs "${APP}" 2>&1 | grep -q "\[DEMO\] Nightly reset: restarting" || fail "the reset did not run"
[ "$(docker logs "${APP}" 2>&1 | grep -c "\[DEMO\] Demo ready")" -ge 2 ] || fail "the demo did not come back after the reset"
wait_healthy
[ "$(count)" -eq "${fresh}" ] || fail "the reset did not restore the quarantine ($(count) != ${fresh})"
[ "$(docker inspect -f '{{.RestartCount}}' "${APP}")" = "0" ] || fail "the reset relied on a container restart"
echo "  ok: visitor change gone, demo rebuilt in the same container"

echo
echo "DEMO SMOKE OK"
