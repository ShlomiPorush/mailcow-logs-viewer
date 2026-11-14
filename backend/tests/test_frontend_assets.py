"""A changed frontend file must get a new URL so browsers do not keep the old one."""
import hashlib

from app.frontend_assets import stamp_asset_versions


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def test_local_assets_get_a_content_hash(tmp_path):
    (tmp_path / 'assets' / 'css').mkdir(parents=True)
    (tmp_path / 'assets' / 'css' / 'ui.css').write_bytes(b'body{}')
    (tmp_path / 'app.js').write_bytes(b'console.log(1)')
    html = ('<link href="/static/assets/css/ui.css?v=32">'
            '<script src="/static/app.js?v=52"></script>')
    out = stamp_asset_versions(html, str(tmp_path))
    assert f'/static/assets/css/ui.css?v={_digest(b"body{}")}' in out
    assert f'/static/app.js?v={_digest(b"console.log(1)")}' in out


def test_a_changed_file_gets_a_new_stamp(tmp_path):
    asset = tmp_path / 'app.js'
    asset.write_bytes(b'one')
    html = '<script src="/static/app.js?v=1"></script>'
    first = stamp_asset_versions(html, str(tmp_path))
    asset.write_bytes(b'two')
    assert stamp_asset_versions(html, str(tmp_path)) != first


def test_missing_and_outside_files_are_left_alone(tmp_path):
    html = ('<script src="/static/missing.js?v=3"></script>'
            '<script src="/static/../secret.js?v=3"></script>')
    assert stamp_asset_versions(html, str(tmp_path)) == html
