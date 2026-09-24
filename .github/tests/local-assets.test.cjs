// The browser loads nothing from outside the app: no CDN, no web fonts, no
// remote images (see "Everything is served locally" in
// documentation/UI_Behavior_Catalog.md). Links a user clicks (<a href>) are fine.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const FRONTEND = path.join(__dirname, '..', '..', 'frontend');
const EXTERNAL = /^(?:[a-z][a-z0-9+.-]*:)?\/\//i;

function cssFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) return cssFiles(p);
        return e.name.endsWith('.css') ? [p] : [];
    });
}

test('HTML pages load scripts, styles, icons and images only from the app', () => {
    const external = [];
    for (const page of ['index.html', 'login.html']) {
        const html = fs.readFileSync(path.join(FRONTEND, page), 'utf8');
        for (const m of html.matchAll(/<(script|link|img|iframe|source|video|audio)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
            if (EXTERNAL.test(m[2])) external.push(`${page}: <${m[1]}> ${m[2]}`);
        }
    }
    assert.deepEqual(external, []);
});

test('stylesheets load fonts and images only from the app, and every file exists', () => {
    const problems = [];
    for (const file of cssFiles(path.join(FRONTEND, 'assets'))) {
        const css = fs.readFileSync(file, 'utf8');
        const rel = path.relative(FRONTEND, file);
        for (const m of css.matchAll(/@import\s+(?:url\()?\s*["']?([^"')\s;]+)/g)) {
            if (EXTERNAL.test(m[1])) problems.push(`${rel}: @import ${m[1]}`);
        }
        for (const m of css.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)) {
            const target = m[1];
            if (target.startsWith('data:')) continue;
            if (EXTERNAL.test(target)) { problems.push(`${rel}: url(${target})`); continue; }
            if (target.startsWith('/')) continue;   // absolute app path, served by the backend
            const resolved = path.resolve(path.dirname(file), target.split(/[?#]/)[0]);
            if (!fs.existsSync(resolved)) problems.push(`${rel}: url(${target}) does not exist`);
        }
    }
    assert.deepEqual(problems, []);
});
