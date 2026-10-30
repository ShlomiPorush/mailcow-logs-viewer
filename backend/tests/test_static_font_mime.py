"""Web fonts under /static are served as font/woff2.

The slim Python image has no MIME entry for .woff2, so without the
registration in app.main the fonts went out as application/octet-stream.
"""
import mimetypes

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import app.main  # noqa: E402,F401  (registers the MIME type on import)


def test_woff2_is_served_as_a_font():
    assert mimetypes.guess_type("onest-latin.woff2")[0] == "font/woff2"
