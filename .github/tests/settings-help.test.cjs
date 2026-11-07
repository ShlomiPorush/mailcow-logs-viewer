// The short line under a Settings field and the longer help behind its "i":
// every entry belongs to a real field, and the text follows the rules for both.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const frontend = path.join(__dirname, '../../frontend');
const settings = fs.readFileSync(path.join(frontend, 'settings.js'), 'utf8');
const utils = fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8');

const table = name => {
    const start = settings.indexOf(`var ${name} = {`);
    assert.notEqual(start, -1, name);
    const end = settings.indexOf('\n};\n', start) + 3;
    const box = {};
    vm.runInNewContext(settings.slice(start, end), box);
    return box[name];
};
const LINES = table('SETTINGS_FIELD_DESCRIPTIONS');
const HELP = table('SETTINGS_FIELD_HELP');
const tabs = settings.slice(settings.indexOf('var SETTINGS_EDIT_TABS'), settings.indexOf('var SETTINGS_TAB_GROUPS'));
const texts = value => [].concat(value);

function uiHelp(...args) {
    const start = utils.indexOf('let uiHelpSeq = 0;');
    const end = utils.indexOf('// Under the whole field');
    const box = { escapeHtml: s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') };
    vm.runInNewContext(`${utils.slice(start, end)}\nthis.uiHelp = uiHelp;`, box);
    return box.uiHelp(...args);
}

test('every line and every help text belongs to a field in a Settings tab', () => {
    for (const key of [...Object.keys(LINES), ...Object.keys(HELP)]) {
        assert.ok(tabs.includes(`'${key}'`), `${key} is in no tab`);
    }
});

test('the line under a field stays short', () => {
    for (const [key, line] of Object.entries(LINES)) {
        const sentences = line.split(/(?<=[.!?])\s+/).length;
        assert.ok(sentences <= 2, `${key}: ${sentences} sentences`);
    }
});

test('neither text repeats what the screen shows or uses a dash the app does not write', () => {
    for (const [key, value] of [...Object.entries(LINES), ...Object.entries(HELP)]) {
        for (const text of texts(value)) {
            assert.doesNotMatch(text, /\bDefault:/, `${key}: Reset to default names the default`);
            assert.doesNotMatch(text, /[\u2010-\u2015\u2212\u2190-\u21ff]/, `${key}: dash or arrow`);
            assert.match(text, /[.!?]$|https?:\/\/\S+$/, `${key}: ends without a full stop: ${text}`);
        }
    }
});

test('a field with help has a name the button can use, and its text in paragraphs', () => {
    const html = uiHelp('Rspamd URL', ['First <b>.', 'Second.']);
    const id = html.match(/popovertarget="(ui-help-\d+)"/)[1];
    assert.match(html, /aria-label="More about Rspamd URL"/);
    assert.match(html, new RegExp(`<div id="${id}" popover class="ui-field-help-panel">`));
    assert.match(html, /<p>First &lt;b&gt;\.<\/p><p>Second\.<\/p>/);
    assert.match(uiHelp('Name', 'One text.'), /<p>One text\.<\/p>/);
});

test('field help is not the button beside a page title', () => {
    assert.doesNotMatch(utils.slice(utils.indexOf('let uiHelpSeq = 0;'), utils.indexOf('// Called once at startup')), /\.ui-help-btn|"ui-help-btn"/);
});
