#!/usr/bin/env python3
"""Browser pass over every page of a running mailcow Logs Viewer.

Opens each SPA route in headless Chromium, clicks every control that only
switches what is shown (sub-tabs, views, date presets, filters), opens the
detail views of the seeded data (smoke_seed.py) and fails on:

  - an uncaught JavaScript error,
  - an inline handler (onclick="fn()" and friends) whose function does not
    exist at runtime, including handlers rendered from API data,
  - an API call to a path the backend does not serve (checked against
    /openapi.json, because the SPA catch-all answers unknown paths with 200),
  - an API response of 404 or any 5xx that is not listed in EXPECTED_ERRORS,
  - an API answer that does not match what /openapi.json says the operation
    returns (operations that document nothing yet are counted as skipped).

Buttons that act (run, save, delete, ban, release) are never clicked.

Usage: python ui_smoke.py <base url>
Run it with: UI_SMOKE=1 bash .github/scripts/smoke.sh <image tag>
It runs inside mcr.microsoft.com/playwright/python; CI does not run it.
"""
import json
import re
import sys
import urllib.request
from urllib.parse import urlparse

from jsonschema import Draft202012Validator
from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:8080'

# Controls whose handler only changes the view. Matched against the full
# onclick attribute; everything else is left alone.
SAFE_CLICK = re.compile(
    r'^\s*(?:event\.stopPropagation\(\);?\s*)?'
    r'(?:\w*[Ss]witch\w*(?:Tab|View)|selectDatePreset|selectMessagesDatePreset|setLogTimePreset'
    r'|(?:apply|clear|reset)\w*Filters|toggle\w*DateRangePicker|toggleDarkMode)\s*\(')

# Controls that open a detail view of seeded data (read-only). Each function is
# clicked at most OPEN_CAP times per page, so a long list does not dominate.
OPEN_CLICK = re.compile(
    r'^\s*(?:event\.stopPropagation\(\);?\s*)?'
    r'(?:viewMessageDetails|loadDomainOverview|loadSourceDetails)\s*\(')
OPEN_CAP = 2

# View switches wired with addEventListener instead of an inline handler.
SAFE_SELECTORS = '.settings-edit-tab'

# API errors that are the correct answer in the smoke environment, where
# mailcow is an unreachable placeholder. Each entry: (method, path regex, status, reason).
# A read from mailcow that fails answers 502 (Bad Gateway); Fail2ban answers 503.
MAILCOW_DOWN = 'reads from mailcow, which is an unreachable placeholder in the smoke test'
EXPECTED_ERRORS = [
    ('GET', r'^/api/status/(version|containers|mailcow-info|storage)$', 502, MAILCOW_DOWN),
    ('GET', r'^/api/(queue|quarantine)$', 502, MAILCOW_DOWN),
    ('GET', r'^/api/fail2ban$', 503, MAILCOW_DOWN),
    ('GET', r'^/api/domains/all$', 502, MAILCOW_DOWN),
]

MAX_CLICKS_PER_PAGE = 60

# Runs in the page: clicks the next not-yet-clicked, visible control that is
# safe to press, and returns its key (or null when there is none left).
CLICK_NEXT_JS = r"""([safePattern, openPattern, selectors, openCap]) => {
    const state = (window.__uiSmoke ||= { seen: new Set(), perFn: {} });
    const safe = new RegExp(safePattern), open = new RegExp(openPattern);
    const visible = el => {
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
    };
    const candidates = [];
    for (const el of document.querySelectorAll('[onclick]')) {
        const v = el.getAttribute('onclick');
        if (safe.test(v)) candidates.push([el, v, null]);
        else if (open.test(v)) candidates.push([el, v, v.match(/(viewMessageDetails|loadDomainOverview|loadSourceDetails)/)[1]]);
    }
    for (const el of document.querySelectorAll(selectors)) {
        candidates.push([el, 'selector:' + (el.dataset.tab || el.textContent.trim()), null]);
    }
    for (const [el, key, fn] of candidates) {
        if (state.seen.has(key) || !visible(el)) continue;
        if (fn) {
            if ((state.perFn[fn] || 0) >= openCap) continue;
            state.perFn[fn] = (state.perFn[fn] || 0) + 1;
        }
        state.seen.add(key);
        el.click();
        return key;
    }
    return null;
}"""

# Runs in the page: every inline handler must resolve to a function. Uses the
# Function constructor so top-level const/let functions are visible too.
MISSING_HANDLERS_JS = r"""() => {
    const attrs = ['onclick', 'onchange', 'oninput', 'onsubmit', 'onkeyup', 'onkeydown'];
    const skip = new Set(['if', 'for', 'while', 'switch', 'return', 'typeof', 'function', 'new']);
    const out = new Set();
    for (const el of document.querySelectorAll(attrs.map(a => `[${a}]`).join(','))) {
        for (const a of attrs) {
            const v = el.getAttribute(a);
            if (!v) continue;
            const code = v.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, "''");
            for (const m of code.matchAll(/(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
                const name = m[2];
                if (skip.has(name)) continue;
                let kind;
                try { kind = (new Function(`return typeof ${name}`))(); } catch (e) { kind = 'error'; }
                if (kind !== 'function') out.add(`${name}() in ${a}="${v.trim().slice(0, 90)}"`);
            }
        }
    }
    return [...out];
}"""


def fetch(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return r.read().decode('utf-8')


def route_matchers(spec):
    """(regex, path template) for every path the backend serves, from its OpenAPI schema.
    Templates with fewer parameters come first, so /api/messages/new is not taken
    for a /api/messages/{id}."""
    out = []
    for p in sorted(spec['paths'], key=lambda t: t.count('{')):
        parts = []
        for seg in p.strip('/').split('/'):
            if re.fullmatch(r'\{[^}]+:path\}', seg):
                parts.append('.+')
            elif re.fullmatch(r'\{[^}]+\}', seg):
                parts.append('[^/]+')
            else:
                parts.append(re.escape(seg))
        out.append((re.compile('^/' + '/'.join(parts) + '/?$'), p))
    return out


# Answered by the auth middleware or the origin guard for any call; a route
# documents them only when it gives them itself (backend/tests/contract.py)
APP_WIDE_STATUSES = {401, 403, 429}


def documented_schema(schema):
    """Whether a schema says anything: FastAPI's default ({}) and any-object do not."""
    if not schema:
        return False
    return not (schema.get('type') == 'object' and not schema.get('properties')
                and schema.get('additionalProperties', True) in (True, {}))


def is_documented(operation):
    """Whether an operation says what it returns: a body schema, or a 3xx/204 without a body."""
    for code, response in (operation.get('responses') or {}).items():
        if code[:1] not in '23':
            continue
        content = response.get('content')
        if not content:
            if code[:1] == '3' or code == '204':
                return True
        elif any(documented_schema(media.get('schema') or {}) for media in content.values()):
            return True
    return False


def answer_problem(spec, operation, status, content_type, body):
    """What is wrong with an answer against the operation's documentation (as tests/contract.py),
    or None. Returns 'skip' when the operation documents nothing yet."""
    if not is_documented(operation):
        return 'skip'
    responses = operation.get('responses') or {}
    response = responses.get(str(status))
    if response is None:
        return None if status in APP_WIDE_STATUSES else f'HTTP {status}, a status its documentation does not list'
    content = response.get('content') or {}
    media = (content_type or '').split(';')[0].strip()
    if not content or not body:
        return None
    if media not in content:
        return f'HTTP {status} as {media}, documented as {", ".join(content)}'
    schema = content[media].get('schema') or {}
    if media != 'application/json' or not schema:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return f'HTTP {status} with a body that is not JSON'
    errors = list(Draft202012Validator({**schema, 'components': spec.get('components', {})}).iter_errors(data))
    if not errors:
        return None
    return f'HTTP {status} does not match its documentation: ' + '; '.join(
        f"{'/'.join(str(p) for p in e.absolute_path) or '(top)'}: {e.message[:200]}" for e in errors[:3])


def spa_routes():
    """URL paths for every page the router accepts (router.js is the source)."""
    router = fetch('/static/router.js')
    valid = re.findall(r"'([^']+)'", re.search(r'const VALID_ROUTES = \[(.*?)\];', router, re.S).group(1))
    display = dict(re.findall(r"'([^']+)':\s*'([^']+)'",
                              re.search(r'const ROUTE_DISPLAY = \{(.*?)\};', router, re.S).group(1)))
    return [display.get(r, r) for r in valid]


def expected(method, path, status):
    return any(m == method and re.search(rx, path) and s == status for m, rx, s, _ in EXPECTED_ERRORS)


# The API reference (/docs) runs the vendored Scalar bundle, which can talk to
# scalar.com in several ways that frontend/api-docs.js turns off. Only a real
# browser shows whether a new bundle still honours that, so run this pass
# after every Scalar update.
SCALAR_FEATURES = ['Open API Client', 'Ask AI', 'Generate MCP', 'Connect MCP', 'Generate SDK',
                   'Developer Tools', 'Share', 'Register', 'Deploy']
# "Powered by Scalar": plain links that carry nothing about this server
SCALAR_CREDITS = {'https://scalar.com/?utm_source=powered-by&utm_medium=api-reference', 'https://www.scalar.com/'}


def check_api_docs(browser):
    problems, outside = [], set()
    context = browser.new_context(viewport={'width': 1440, 'height': 900})
    context.on('request', lambda r: urlparse(r.url).scheme in ('http', 'https')
               and not r.url.startswith(BASE + '/') and outside.add(r.url))
    page = context.new_page()

    def check_page(step):
        for href in page.eval_on_selector_all('a[href]', 'as => as.map(a => a.href)'):
            if 'scalar.com' in href and href not in SCALAR_CREDITS:
                problems.append(f'{step}: link to {href}')
        text = page.evaluate('document.body.innerText')
        problems.extend(f"{step}: Scalar's '{t}' is shown" for t in SCALAR_FEATURES if t in text)

    page.goto(f'{BASE}/docs', wait_until='networkidle', timeout=60000)
    page.wait_for_selector("a[href*='GET/api/health']", state='attached', timeout=30000)
    # A second reference means the bundle started one of its own, with Scalar's defaults
    if page.locator('.darklight-reference').count() != 1:
        problems.append('more than one reference on the page')
    check_page('reference')

    page.goto(f'{BASE}/docs#GET/api/health', wait_until='networkidle')
    page.locator("section[id$='GET/api/health']").get_by_role('button', name='Test Request').first.click()
    page.get_by_role('button', name='Send').first.click()
    page.wait_for_load_state('networkidle')
    page.wait_for_timeout(500)
    check_page('Test Request')
    if '200 OK' not in page.locator('[role=dialog]').first.inner_text():
        problems.append('Test Request on GET /api/health did not show 200 OK')

    problems.extend(f'request outside the app: {u}' for u in sorted(outside))
    context.close()
    print(f'  docs: {"problems found" if problems else "Scalar stays on this server, Test Request works"}')
    return problems


def main():
    spec = json.loads(fetch('/openapi.json'))
    routes = route_matchers(spec)
    pages = spa_routes()
    failures, warnings = [], []
    checked, skipped = set(), set()

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport={'width': 1440, 'height': 900})
        page = context.new_page()
        where = {'page': '-'}

        def fail(msg):
            failures.append(f"[{where['page']}] {msg}")

        page.on('pageerror', lambda e: fail(f'uncaught JavaScript error: {e}'))
        page.on('console', lambda m: m.type == 'error' and warnings.append(f"[{where['page']}] console: {m.text[:200]}"))

        def on_response(resp):
            u = urlparse(resp.url)
            if not u.path.startswith('/api/'):
                return
            method = resp.request.method
            template = next((t for rx, t in routes if rx.match(u.path)), None)
            if template is None:
                fail(f'{method} {u.path}: the backend has no such route')
                return
            if resp.status == 404 or resp.status >= 500:
                if not expected(method, u.path, resp.status):
                    fail(f'{method} {u.path}: HTTP {resp.status}')
            operation = (spec['paths'].get(template) or {}).get(method.lower())
            if not operation:
                return
            try:
                body = resp.body()
            except Exception:   # a redirect or an aborted request has none
                body = b''
            problem = answer_problem(spec, operation, resp.status, resp.headers.get('content-type', ''), body)
            if problem == 'skip':
                skipped.add(f'{method} {template}')
            else:
                checked.add(f'{method} {template}')
                if problem:
                    fail(f'{method} {u.path}: {problem}')
        page.on('response', on_response)

        def check_handlers():
            for missing in page.evaluate(MISSING_HANDLERS_JS):
                fail(f'handler not defined: {missing}')

        for route in pages:
            where['page'] = route
            page.goto(f'{BASE}/{route}', wait_until='networkidle', timeout=60000)
            page.wait_for_timeout(300)
            check_handlers()

            clicked = set()
            for _ in range(MAX_CLICKS_PER_PAGE):
                # Re-query each time: a click may re-render the page. The click
                # is dispatched on the element itself so an open modal or
                # overlay cannot swallow it; handler exceptions still surface
                # as 'pageerror'.
                target = page.evaluate(CLICK_NEXT_JS, [SAFE_CLICK.pattern, OPEN_CLICK.pattern, SAFE_SELECTORS, OPEN_CAP])
                if not target:
                    break
                clicked.add(target)
                page.wait_for_load_state('networkidle', timeout=30000)
                page.wait_for_timeout(150)
                check_handlers()
            opened = sorted({k.split('(')[0].split(';')[-1].strip() for k in clicked if OPEN_CLICK.match(k)})
            print(f'  {route}: loaded, {len(clicked)} controls clicked'
                  + (f", opened: {', '.join(opened)}" if opened else ''))

        where['page'] = 'docs'
        for problem in check_api_docs(browser):
            fail(problem)
        browser.close()

    print(f'\n  answers checked against /openapi.json: {len(checked)} operations; '
          f'not documented yet, so not checked: {len(skipped)}')
    for w in dict.fromkeys(warnings):
        print(f'  warning {w}')
    if failures:
        print(f'\n{len(failures)} problem(s):')
        for f in dict.fromkeys(failures):
            print(f'  FAIL {f}')
        return 1
    print(f'\nbrowser pass OK: {len(pages)} pages')
    return 0


if __name__ == '__main__':
    sys.exit(main())
