"""
The demo notice on every page.

The regular frontend knows nothing about the demo. This middleware adds a
slim notice at the top of the main column of every HTML page the app
serves, styled with the interface's own theme variables so it follows the
light and dark themes.

DEMO_PREVIEW_LABEL adds a second tag next to "Demo", for example
"v3 preview" while the demo runs a version that is not released yet. It is
empty by default, so a build that does not set it shows no label.
"""
import html
import os

INSTALL_URL = "https://github.com/ShlomiPorush/mailcow-logs-viewer/blob/main/documentation/GETTING_STARTED.md"
MARKER = b'<div class="ui-main">'

STYLE = """
.demo-banner { flex: none; display: flex; flex-wrap: wrap; align-items: center; gap: 6px 12px;
  padding: 8px var(--ui-pad-x, 16px); background: var(--ui-panel); color: var(--ui-ink);
  border-bottom: 1px solid var(--ui-line); font-size: var(--ui-fs-sm, 12.5px); line-height: 1.4; }
.demo-banner-tag { padding: 2px 8px; border-radius: 999px; background: var(--ui-accent);
  color: var(--ui-on-accent); font-weight: 600; letter-spacing: .02em; }
.demo-banner-preview { padding: 1px 8px; border-radius: 999px; border: 1px solid var(--ui-line);
  color: var(--ui-ink); font-weight: 600; white-space: nowrap; }
.demo-banner-text { color: var(--ui-muted); }
.demo-banner a { color: var(--ui-ink); font-weight: 600; text-decoration: underline;
  text-underline-offset: 3px; margin-inline-start: auto; }
.demo-banner a:focus-visible { outline: 2px solid var(--ui-focus); outline-offset: 2px; border-radius: 4px; }
.demo-banner-short { display: none; }
@media (max-width: 760px) {
  .demo-banner { flex-wrap: nowrap; }
  .demo-banner-long { display: none; }
  .demo-banner-short { display: inline; }
}
"""


PREVIEW_LABEL_MAX = 40


def banner_html(preview_label: str = "") -> bytes:
    label = (preview_label or "").strip()[:PREVIEW_LABEL_MAX]
    preview = f'<span class="demo-banner-preview">{html.escape(label)}</span>' if label else ""
    return (
        f"<style>{STYLE}</style>"
        '<aside class="demo-banner" aria-label="Demo notice">'
        '<span class="demo-banner-tag">Demo</span>'
        f"{preview}"
        '<span class="demo-banner-text"><span class="demo-banner-long">Fictional data, no real mail server. '
        "Anything you change is reset automatically on a regular schedule.</span>"
        '<span class="demo-banner-short">Fictional data, resets automatically</span></span>'
        f'<a href="{INSTALL_URL}" target="_blank" rel="noopener">'
        '<span class="demo-banner-long">Install it on your server</span><span class="demo-banner-short">Install</span></a>'
        "</aside>"
    ).encode()


BANNER = banner_html(os.environ.get("DEMO_PREVIEW_LABEL", ""))


def inject(body: bytes) -> bytes:
    """Put the notice at the top of the main column, once."""
    if MARKER not in body or b'class="demo-banner"' in body:
        return body
    return body.replace(MARKER, MARKER + BANNER, 1)


class DemoBannerMiddleware:
    """Pure ASGI: buffers only HTML responses, passes everything else through."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "GET":
            await self.app(scope, receive, send)
            return

        start = None
        chunks = []

        async def capture(message):
            nonlocal start
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers") or [])
                if headers.get(b"content-type", b"").startswith(b"text/html"):
                    start = message
                    return
                await send(message)
                return
            if start is None:
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body"):
                return
            body = inject(b"".join(chunks))
            headers = [(k, v) for k, v in start.get("headers") or [] if k != b"content-length"]
            headers.append((b"content-length", str(len(body)).encode()))
            await send({**start, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        await self.app(scope, receive, capture)
