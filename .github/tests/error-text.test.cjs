// A request that fails says what happened in plain words (utils.js): the server's own
// reason when it gave one, else what its status means; a network failure, a timeout,
// an answer that is not JSON (a proxy's error page) and a fault in the page get words
// of their own. The page never shows the browser's or the parser's text, nor a status
// line ("HTTP 500: "), so no page reads error.message or statusText itself.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');
const utils = fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8');
// The four helpers and the set they share, up to the next section of utils.js
const helperStart = utils.indexOf('function uiApiErrorText(');
const helperEnd = utils.indexOf('\n// ====', helperStart);
assert.ok(helperStart > 0 && helperEnd > helperStart, 'the error-text helpers must be in utils.js');
const context = vm.createContext({});
vm.runInContext(utils.slice(helperStart, helperEnd), context);
const { uiHttpErrorText, uiErrorText, uiReadJson } = context;

const DID_NOT_ANSWER = 'The server did not answer. It may be restarting';
const NO_CONNECTION = 'Could not reach the server. Check the connection';

test('the server\'s own reason comes first', () => {
    assert.equal(uiHttpErrorText(400, { detail: 'Rule name is required' }), 'Rule name is required');
    assert.equal(uiHttpErrorText(409, { detail: { code: 'map_changed', message: 'The map changed since you opened it' } }),
        'The map changed since you opened it');
    // A validation list (FastAPI 422): each field with its problem
    assert.equal(uiHttpErrorText(422, { detail: [
        { loc: ['body', 'match_value'], msg: 'Field required' },
        { loc: ['body', 'name'], msg: 'String should have at least 1 character' },
    ] }), 'match value: Field required; name: String should have at least 1 character');
});

test('a catch-all or a missing reason says what the status means', () => {
    assert.equal(uiHttpErrorText(500, { detail: 'An error occurred' }),
        'The server hit an error. If it keeps happening, check the app log');
    assert.equal(uiHttpErrorText(500, null), 'The server hit an error. If it keeps happening, check the app log');
    // A proxy's error page is not JSON: no body at all
    for (const status of [502, 503, 504]) assert.equal(uiHttpErrorText(status, null), DID_NOT_ANSWER);
    assert.equal(uiHttpErrorText(404, null), 'Not found. It may have been removed');
    assert.equal(uiHttpErrorText(429, {}), 'Too many requests. Wait a moment');
    assert.equal(uiHttpErrorText(413, null), 'Too large for the server');
    assert.equal(uiHttpErrorText(418, null), 'The server refused the request (HTTP 418)');
    assert.equal(uiHttpErrorText(400, { detail: [] }), 'The server refused the request (HTTP 400)');
});

test('every catch-all the server words an unexpected error with says nothing to the page', () => {
    const backend = path.join(__dirname, '../../backend/app');
    // main.py's global handler and utils.internal_error, outside debug mode
    const sources = [['main.py', /settings\.debug else "([^"]+)"/], ['utils.py', /settings\.debug else "([^"]+)"/]];
    for (const [file, pattern] of sources) {
        const said = fs.readFileSync(path.join(backend, file), 'utf8').match(pattern);
        assert.ok(said, `the catch-all text of ${file} must be found`);
        assert.equal(uiHttpErrorText(500, { detail: said[1] }), 'The server hit an error. If it keeps happening, check the app log', file);
    }
});

test('a reason becomes a sentence once', () => {
    assert.equal(context.uiSentence('Could not reach the server. Check the connection'), 'Could not reach the server. Check the connection.');
    assert.equal(context.uiSentence('You do not have permission for this.'), 'You do not have permission for this.');
});

test('what a request threw, in words', () => {
    // Chrome, Firefox and Safari word a network failure differently
    assert.equal(uiErrorText(new TypeError('Failed to fetch')), NO_CONNECTION);
    assert.equal(uiErrorText(new TypeError('NetworkError when attempting to fetch resource.')), NO_CONNECTION);
    assert.equal(uiErrorText(new TypeError('Load failed')), NO_CONNECTION);
    // A body that is not JSON
    let parseError;
    try { JSON.parse('<html><body>502 Bad Gateway</body></html>'); } catch (e) { parseError = e; }
    assert.equal(parseError.name, 'SyntaxError');
    assert.match(uiErrorText(parseError), /could not read/);
    // A request that ran out of time (authenticatedFetch's timeout aborts it)
    assert.match(uiErrorText(new DOMException('The operation was aborted.', 'AbortError')), /took too long/);
    const timedOut = new Error('signal timed out');
    timedOut.name = 'TimeoutError';
    assert.match(uiErrorText(timedOut), /took too long/);
    // A fault in the page's own code
    assert.equal(uiErrorText(new TypeError("Cannot read properties of undefined (reading 'map')")),
        'Something went wrong in the page. Reload it');
    assert.equal(uiErrorText(new ReferenceError('x is not defined')), 'Something went wrong in the page. Reload it');
    // Words already meant for a person stay as they are
    assert.equal(uiErrorText(new Error('Rule name is required')), 'Rule name is required');
    assert.equal(uiErrorText('The map changed'), 'The map changed');
    assert.equal(uiErrorText(new Error('')), 'Something went wrong');
    assert.equal(uiErrorText(null), 'Something went wrong');
});

test('a body that is not JSON reads as null', async () => {
    assert.deepEqual(await uiReadJson({ json: async () => ({ detail: 'x' }) }), { detail: 'x' });
    assert.equal(await uiReadJson({ json: async () => { throw new SyntaxError("Unexpected token '<'"); } }), null);
});

// ----------------------------------------------------------------- the pages

const pages = fs.readdirSync(frontend).filter(name => name.endsWith('.js')).map(name => {
    const source = fs.readFileSync(path.join(frontend, name), 'utf8');
    const lines = source.split(/\r?\n/);
    // In utils.js the helpers themselves read error.message
    const skip = name === 'utils.js'
        ? [source.slice(0, helperStart).split('\n').length, source.slice(0, helperEnd).split('\n').length] : [0, 0];
    return { name, lines: lines.map((text, i) => ({ text, line: i + 1 })).filter(({ line }) => line < skip[0] || line > skip[1]) };
});
// Not an error: the raw log lines of an address on the Security page
const NOT_AN_ERROR = [/lines\.map\(e => .*escapeHtml\(e\.message \|\| ''\)/];

test('no page shows a status line', () => {
    const found = pages.flatMap(({ name, lines }) => lines.filter(({ text }) => /\.statusText\b/.test(text))
        .map(({ text, line }) => `${name}:${line}: ${text.trim()}`));
    assert.deepEqual(found, [], 'use uiHttpErrorText(response.status, body) or responseError(response)');
    const bare = pages.flatMap(({ name, lines }) => lines.filter(({ text }) => /new Error\(\s*[`'"]HTTP /.test(text))
        .map(({ text, line }) => `${name}:${line}: ${text.trim()}`));
    assert.deepEqual(bare, [], 'throw await responseError(response) instead of an error with a bare status');
});

test('no page shows what a request threw as it is', () => {
    const found = pages.flatMap(({ name, lines }) => lines
        .filter(({ text }) => /\b(error|err|e|ex)\.message\b/.test(text) && !/console\./.test(text)
            && !NOT_AN_ERROR.some(allowed => allowed.test(text)))
        .map(({ text, line }) => `${name}:${line}: ${text.trim()}`));
    assert.deepEqual(found, [], 'show uiErrorText(error) instead');
});
