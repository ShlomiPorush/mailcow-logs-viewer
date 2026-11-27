import mimetypes

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import app.main  # noqa: E402,F401


def test_woff2_is_served_as_a_font():
    assert mimetypes.guess_type("onest-latin.woff2")[0] == "font/woff2"
