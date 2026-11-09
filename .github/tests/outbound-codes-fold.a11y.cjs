// Settings > Outbound in a real DOM (jsdom): a Status code exceptions area starts closed,
// and its line counts each code once, the way the server reads it (5.02.2 is 5.2.2),
// leaving out codes the built-in exceptions already cover while they are on.
// Set A11Y_MODULES to jsdom's node_modules to run it locally (see layers.a11y.cjs).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const modules = process.env.A11Y_MODULES || '/tmp/a11y/node_modules';
const { JSDOM } = require(path.join(modules, 'jsdom'));

const frontend = path.join(__dirname, '../../frontend');
const read = name => fs.readFileSync(path.join(frontend, name), 'utf8');

function area(codes, standard) {
    const dom = new JSDOM('<!doctype html><html lang="en"><head><title>t</title></head><body><form id="f"></form></body></html>',
        { runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://logs.example.com/settings/outbound',
          beforeParse: win => { win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }); } });
    const w = dom.window;
    const run = source => {
        const script = w.document.createElement('script');
        script.textContent = source;
        w.document.head.appendChild(script);
    };
    [read('utils.js'), read('app.js'), read('settings.js')].forEach(run);
    const config = { suppression_hard_bounce_excluded_codes: codes, suppression_hard_bounce_standard_codes: standard };
    w.document.getElementById('f').innerHTML = w.settingsBounceCodes('hard', config, new w.Set(), { suppression_hard_bounce_excluded_codes: '', suppression_hard_bounce_standard_codes: true });
    const box = w.document.querySelector('.ui-set-codes');
    w.settingsShowCodes(box);
    return { w, box, line: () => box.querySelector('[data-codes-summary]').textContent };
}

test('the area starts closed and says what it excludes', () => {
    const { box, line } = area('', true);
    assert.equal(box.querySelector('details.ui-set-codes-fold').open, false);
    assert.equal(line(), 'Built-in codes excluded.');
});

test('each code counts once, as the server reads it', () => {
    assert.equal(area('5.2.1,5.2.1', false).line(), '1 code excluded.');
    assert.equal(area('5.2.1,5.02.1', false).line(), '1 code excluded.');
    assert.equal(area('5.2.1,5.1.1', false).line(), '2 codes excluded.');
    assert.equal(area('', false).line(), 'No codes excluded.');
});

test('a code the built-in exceptions cover does not count while they are on', () => {
    const { w } = area('', true);
    // A code the built-in list covers, in the form a person may have typed in the environment
    const covered = ['5.2.2', '5.7.1', '5.4.1', '5.3.4'].find(code => w.settingsStandardCovers(code));
    assert.ok(covered, 'a built-in code to test with');
    const padded = covered.replace(/\.(\d)$/, '.0$1');
    assert.equal(area(`${padded},5.1.1`, true).line(), 'Built-in codes and 1 additional code excluded.');
    assert.equal(area(`${padded},5.1.1`, false).line(), '2 codes excluded.');
});
