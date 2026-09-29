const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

// Every page must sit directly in the content area. A wrapper opened in one
// page and closed in the wrong place nests the following pages inside it, and
// they vanish whenever that page is hidden - while the div count stays even.
const html = fs.readFileSync(process.env.INDEX_HTML || path.join(__dirname, '../../frontend/index.html'), 'utf8')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '');

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr', 'path', 'circle', 'rect', 'line', 'polyline', 'polygon', 'use']);

function pagesAndParents() {
    const stack = [];
    const pages = [];
    const tag = /<(\/?)([a-zA-Z][\w-]*)([^>]*?)(\/?)>/g;
    let m;
    while ((m = tag.exec(html))) {
        const [, closing, rawName, attrs, selfClosing] = m;
        const name = rawName.toLowerCase();
        if (closing) {
            const at = stack.map(e => e.name).lastIndexOf(name);
            if (at >= 0) stack.length = at;
            continue;
        }
        const cls = (attrs.match(/\bclass="([^"]*)"/) || [])[1] || '';
        const id = (attrs.match(/\bid="([^"]*)"/) || [])[1] || '';
        if (/\btab-content\b/.test(cls)) pages.push({ id, parent: stack[stack.length - 1] });
        if (!selfClosing && !VOID.has(name)) stack.push({ name, cls, id });
    }
    return pages;
}

test('every page sits directly in the content area', () => {
    const pages = pagesAndParents();
    assert.ok(pages.length >= 10, `expected the app pages, found ${pages.length}`);
    for (const page of pages) {
        assert.ok(page.parent && /\bui-content\b/.test(page.parent.cls),
            `${page.id} is inside ${page.parent ? `${page.parent.name}#${page.parent.id}.${page.parent.cls}` : 'nothing'}, not the content area`);
    }
});
