// The "+N" a Messages row shows beside its first recipient (utils.js
// renderRecipientMore): nothing for one recipient, else the other recipients
// counted, with words for the tooltip and for a screen reader.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const frontend = path.join(__dirname, '../../frontend');

function helper() {
    const context = vm.createContext({ window: {}, document: { addEventListener() {} }, console });
    vm.runInContext(fs.readFileSync(path.join(frontend, 'utils.js'), 'utf8'), context);
    return context.renderRecipientMore;
}

test('one recipient, none, or no count at all: no tag', () => {
    const more = helper();
    assert.equal(more({ recipient_count: 1 }), '');
    assert.equal(more({ recipient_count: 0 }), '');
    assert.equal(more({}), '');
    assert.equal(more({ recipient_count: '<b>' }), '');
});

test('more recipients: "+N" with its words, singular and plural', () => {
    const more = helper();
    assert.equal(more({ recipient_count: 2 }),
        '<span class="ui-tag ui-rcpt-more" title="and 1 more recipient"><span aria-hidden="true">+1</span><span class="ui-sr-only"> and 1 more recipient</span></span>');
    assert.match(more({ recipient_count: 4 }), /title="and 3 more recipients"><span aria-hidden="true">\+3<\/span><span class="ui-sr-only"> and 3 more recipients</);
});
