"""
The demo notice: added once to every HTML page, nothing else touched.
"""
import asyncio

from demo.banner import DemoBannerMiddleware, inject

PAGE = b'<html><body><div class="ui-shell"><div class="ui-main"><div class="ui-content"></div></div></div></body></html>'


def _serve(body, content_type, method="GET"):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", content_type), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request"}

    asyncio.run(DemoBannerMiddleware(app)({"type": "http", "method": method, "path": "/"}, receive, send))
    headers = dict(sent[0]["headers"])
    return b"".join(m.get("body", b"") for m in sent[1:]), headers


def test_the_notice_opens_the_main_column_once():
    body = inject(PAGE)
    assert body.count(b'class="demo-banner"') == 1
    assert body.index(b'class="demo-banner"') > body.index(b'<div class="ui-main">')
    assert body.index(b'class="demo-banner"') < body.index(b'<div class="ui-content">')
    assert inject(body) == body
    assert b"reset automatically on a regular schedule" in body


def test_html_pages_get_the_notice_with_a_correct_length():
    body, headers = _serve(PAGE, b"text/html; charset=utf-8")
    assert b"demo-banner" in body
    assert headers[b"content-length"] == str(len(body)).encode()


def test_other_responses_pass_untouched():
    data = b'{"ok": true, "html": "<div class=\\"ui-main\\">"}'
    body, headers = _serve(data, b"application/json")
    assert body == data
    body, _ = _serve(PAGE, b"text/html", method="POST")
    assert body == PAGE


def test_the_default_text_is_shown_unless_a_notice_is_set():
    from demo.banner import banner_html
    for value in ("", "   "):
        assert b"reset automatically on a regular schedule" in banner_html(value)


def test_a_notice_replaces_the_whole_text_escaped_and_short():
    from demo.banner import NOTICE_MAX, banner_html
    body = banner_html("  v3 preview.\t Fictional data.  ")
    assert b'<span class="demo-banner-text">v3 preview. Fictional data.</span>' in body
    assert b"reset automatically on a regular schedule" not in body
    assert b"Install it on your server" in body and b">Demo<" in body
    assert b"a&lt;b&gt;&quot;" in banner_html('a<b>"')
    long = banner_html("x" * 500)
    assert b"x" * NOTICE_MAX in long and b"x" * (NOTICE_MAX + 1) not in long
