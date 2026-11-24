const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test, afterEach } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');
const SCRIPTS = ['utils.js', 'router.js', 'app.js', 'settings.js'].map(read);
const HTML = (() => {
    const dom = new JSDOM(read('index.html'));
    dom.window.document.querySelectorAll('script[src], link').forEach(el => el.remove());
    return dom.serialize();
})();

const opened = [];
afterEach(() => { while (opened.length) opened.pop().close(); });

function page(result) {
    const dom = new JSDOM(HTML.replace('</head>', '<style>.hidden { display: none; }</style></head>'), {
        runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/settings/maxmind',
        beforeParse: win => {
            win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
            win.fetch = () => new Promise(() => {});
            win.console = { log() {}, info() {}, warn() {}, error() {}, debug() {} };
        },
    });
    const w = dom.window;
    opened.push(w);
    if (!w.document.scrollingElement) Object.defineProperty(w.document, 'scrollingElement', { value: w.document.documentElement });
    w.Element.prototype.getClientRects = function () {
        return this.isConnected && !this.closest('.hidden') ? [{}] : [];
    };
    for (const source of SCRIPTS) {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    }
    w.showToast = () => {};
    const none = { available: false };
    w.authenticatedFetch = async url => {
        const body = url === '/api/settings/maxmind/validate' ? { valid: true }
            : url === '/api/settings/geoip/status' ? { configured: true, job_status: 'idle', databases: { City: none, ASN: none } }
            : {};
        return { ok: true, status: 200, json: async () => body };
    };
    w.geoipDownloadRun = async () => result;
    return w;
}

async function until(condition, limit = 3000) {
    const end = Date.now() + limit;
    while (Date.now() < end) {
        if (condition()) return true;
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    return !!condition();
}

for (const [name, result, color] of [
    ['a failed download ends the bar red and full', { started: true, ok: false, error: 'Could not download the location database from MaxMind.' }, 'ui-fail'],
    ['a download that did not finish in time ends the bar amber and full', { started: true, ok: null }, 'ui-warn'],
]) {
    test(`GeoIP setup: ${name}`, async () => {
        const w = page(result);
        w.showGeoIPSetupModal();
        const bar = () => w.document.getElementById('geoip-progress-bar');
        assert.ok(await until(() => bar() && bar().classList.contains(color)), `the bar is ${color}: ${bar() && bar().className}`);
        assert.ok(!bar().classList.contains('ui-meter-info'), 'no longer the blue in-progress bar');
        assert.equal(w.document.getElementById('geoip-progress-fill').style.width, '100%');
    });
}
