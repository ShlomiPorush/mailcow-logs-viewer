// The Tailwind utilities are compiled once into frontend/assets/css/utilities.css
// (.github/scripts/build-utilities-css.sh) instead of by a browser runtime. A
// class name assembled at runtime, like bg-${color}-100, is invisible to that
// build and must be listed in the safelist of .github/tailwind/tailwind.config.cjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const ROOT = path.join(__dirname, '..', '..');
const FRONTEND = path.join(ROOT, 'frontend');
const config = require(path.join(ROOT, '.github', 'tailwind', 'tailwind.config.cjs'));
const safelist = new Set(config.safelist);
// The colours the scripts pass into those templates (see app.js)
const RUNTIME_COLOURS = ['gray', 'green', 'red', 'yellow', 'orange'];

function scripts() {
    return fs.readdirSync(FRONTEND).filter(f => f.endsWith('.js')).map(f => [f, fs.readFileSync(path.join(FRONTEND, f), 'utf8')]);
}

test('no page loads the Tailwind browser runtime', () => {
    for (const page of ['index.html', 'login.html']) {
        const html = fs.readFileSync(path.join(FRONTEND, page), 'utf8');
        assert.ok(!/tailwindcss(\.min)?\.js/.test(html), `${page} still loads the Tailwind runtime`);
        assert.ok(!/tailwind\.config\s*=/.test(html), `${page} still configures the Tailwind runtime`);
        assert.match(html, /\/static\/assets\/css\/utilities\.css\?v=\d+/, `${page} does not load utilities.css`);
    }
    assert.ok(!fs.existsSync(path.join(FRONTEND, 'assets', 'libs', 'tailwindcss.min.js')));
});

test('every colour class assembled at runtime is safelisted', () => {
    const missing = [];
    const templated = /\b((?:dark:|hover:|dark:hover:)?(?:bg|text|border))-\$\{\w+\}-(\d+(?:\/\d+)?)/g;
    const concatenated = /'((?:dark:|hover:)?(?:bg|text|border))-' \+ \w+ \+ '-(\d+(?:\/\d+)?)/g;
    for (const [file, text] of scripts()) {
        for (const re of [templated, concatenated]) {
            for (const m of text.matchAll(re)) {
                for (const colour of RUNTIME_COLOURS) {
                    const cls = `${m[1]}-${colour}-${m[2]}`;
                    if (!safelist.has(cls)) missing.push(`${file}: ${cls}`);
                }
            }
        }
    }
    assert.deepEqual([...new Set(missing)], [], 'Add these to the safelist in .github/tailwind/tailwind.config.cjs and rebuild utilities.css');
});

test('the safelisted classes are in the compiled file', () => {
    const css = fs.readFileSync(path.join(FRONTEND, 'assets', 'css', 'utilities.css'), 'utf8');
    const escape = cls => cls.replace(/[:/.]/g, m => '\\' + m);
    const absent = [...safelist].filter(cls => !css.includes('.' + escape(cls)));
    assert.deepEqual(absent, [], 'utilities.css is out of date; run: bash .github/scripts/build-utilities-css.sh');
});
