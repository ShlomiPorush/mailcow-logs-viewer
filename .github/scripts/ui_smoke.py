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
  - an API response of 404 or any 5xx that is not listed in EXPECTED_ERRORS.

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
    r'(?:viewMessageDetails|viewPostfixDetails|loadDomainOverview|loadSourceDetails)\s*\(')
OPEN_CAP = 2

# View switches wired with addEventListener instead of an inline handler.
SAFE_SELECTORS = '.settings-edit-tab'

# API errors that are the correct answer in the smoke environment, where
# mailcow is an unreachable placeholder. Each entry: (method, path regex, status, reason).
MAILCOW_DOWN = 'reads from mailcow, which is an unreachable placeholder in the smoke test'
EXPECTED_ERRORS = [
    ('GET', r'^/api/status/(version|containers|mailcow-info|storage)$', 500, MAILCOW_DOWN),
    ('GET', r'^/api/(fail2ban|queue|quarantine)$', 500, MAILCOW_DOWN),
    ('GET', r'^/api/domains/all$', 500, MAILCOW_DOWN),
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
        else if (open.test(v)) candidates.push([el, v, v.match(/(viewMessageDetails|viewPostfixDetails|loadDomainOverview|loadSourceDetails)/)[1]]);
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


def route_matchers():
    """Regexes for every path the backend serves, from its OpenAPI schema."""
    spec = json.loads(fetch('/openapi.json'))
    out = []
    for p in spec['paths']:
        parts = []
        for seg in p.strip('/').split('/'):
            if re.fullmatch(r'\{[^}]+:path\}', seg):
                parts.append('.+')
            elif re.fullmatch(r'\{[^}]+\}', seg):
                parts.append('[^/]+')
            else:
                parts.append(re.escape(seg))
        out.append(re.compile('^/' + '/'.join(parts) + '/?$'))
    return out


def spa_routes():
    """URL paths for every page the router accepts (router.js is the source)."""
    router = fetch('/static/router.js')
    valid = re.findall(r"'([^']+)'", re.search(r'const VALID_ROUTES = \[(.*?)\];', router, re.S).group(1))
    display = dict(re.findall(r"'([^']+)':\s*'([^']+)'",
                              re.search(r'const ROUTE_DISPLAY = \{(.*?)\};', router, re.S).group(1)))
    return [display.get(r, r) for r in valid]


def expected(method, path, status):
    return any(m == method and re.search(rx, path) and s == status for m, rx, s, _ in EXPECTED_ERRORS)


def main():
    routes = route_matchers()
    pages = spa_routes()
    failures, warnings = [], []

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
            if not any(rx.match(u.path) for rx in routes):
                fail(f'{method} {u.path}: the backend has no such route')
            elif resp.status == 404 or resp.status >= 500:
                if not expected(method, u.path, resp.status):
                    fail(f'{method} {u.path}: HTTP {resp.status}')
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

        browser.close()

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
