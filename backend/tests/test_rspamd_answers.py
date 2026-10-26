"""Every answer the Rspamd map calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the maps with and without the Rspamd
password, Rspamd refusing or answering something that is not its map list (502, or an
error in the list), a save refused for its content (400), a missing Read-Write key
(403), a map changed meanwhile or another save still running (409), and the requests
the calls refuse (404, 400, 422). Rspamd and mailcow are faked at the HTTP client;
nothing leaves the test."""
import json

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.mailcow_api import mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers.rspamd_maps import content_hash  # noqa: E402
from app.services import rspamd_map_lock  # noqa: E402

MAP = 'global_rcpt_blacklist.map'
OTHER = 'global_mime_from_blacklist.map'
# Lines re.compile refuses with OverflowError and RecursionError, not re.error
HUGE_REPEAT = '/a{99999999999}/'
DEEP_NESTING = '/' + '(' * 5000 + 'a' + ')' * 5000 + '/'


@pytest.fixture
def rspamd(monkeypatch):
    """Rspamd's controller and mailcow's map edit behind a fake HTTP client.

    state['maps'] is Rspamd's /maps answer (a list, an httpx.Response, or an
    exception), state['content'] the map's content, state['getmap'] an override
    for /getmap and state['edit'] mailcow's reply to the save."""
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'rspamd_password', 'rspamd-test-password')
    monkeypatch.setattr(settings._inner, 'rspamd_url', None)
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'rw-test-key'})
    state = {
        'maps': [{'map': 7, 'uri': f'/etc/rspamd/custom/{MAP}', 'description': 'Recipient denylist',
                  'editable': True, 'loaded': True}],
        'content': '# denylist\n/^a@example\\.com$/i\n',
        'getmap': None,
        'edit': [{'type': 'success', 'log': ['rspamd', 'edit'], 'msg': ['map_content_saved', MAP]}],
        'writes': [],
    }

    def answer(value):
        if isinstance(value, httpx.Response):
            return value
        return httpx.Response(200, json=value)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == '/rspamd/maps':
            return answer(state['maps'])
        if path == '/rspamd/getmap':
            if state['getmap'] is not None:
                return state['getmap']
            return httpx.Response(200, text=state['content'])
        if path == '/api/v1/edit/rspamd-map':
            sent = json.loads(request.content)['attr']['rspamd_map_data']
            state['writes'].append(sent)
            if isinstance(state['edit'], httpx.Response):
                return state['edit']
            if all(entry.get('type') == 'success' for entry in state['edit']):
                state['content'] = sent.strip() + '\n'
            return httpx.Response(200, json=state['edit'])
        return httpx.Response(404)

    monkeypatch.setattr(mailcow_api, '_get_client', lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(mailcow_api, '_discard_client', lambda client: None)
    yield state


@pytest.fixture
def client(rspamd):
    return TestClient(app, raise_server_exceptions=False)


NOT_JSON = httpx.Response(200, text='<html>Sign in</html>', headers={'content-type': 'text/html'})
REFUSED = httpx.Response(401, text='Unauthorized')


# ---------------------------------------------------------------- configuration and list

def test_config(client):
    r = client.get('/api/rspamd/config')
    assert r.status_code == 200
    assert r.json()['rspamd_configured'] is True and r.json()['rw_key_configured'] is True


def test_list_without_the_rspamd_password(client, monkeypatch):
    monkeypatch.setattr(settings._inner, 'rspamd_password', None)
    r = client.get('/api/rspamd/maps')
    assert r.status_code == 200
    assert r.json()['configured'] is False
    assert any(entry.get('managed_by_suppression') for entry in r.json()['maps'])


def test_list_with_the_state_in_rspamd(client):
    r = client.get('/api/rspamd/maps')
    assert r.status_code == 200
    maps = {entry['filename']: entry for entry in r.json()['maps']}
    assert maps[MAP]['map_id'] == 7 and maps[MAP]['editable'] is True
    assert maps[OTHER]['map_id'] is None and maps[OTHER]['loaded'] is False and 'editable' not in maps[OTHER]


def test_list_when_rspamd_refuses(client, rspamd):
    rspamd['maps'] = REFUSED
    r = client.get('/api/rspamd/maps')
    assert r.status_code == 200
    assert r.json()['error'] and r.json()['configured'] is True


@pytest.mark.parametrize('maps', [NOT_JSON, {'maps': []}, [None], [{'map': 7, 'uri': None}], [{'map': 7}]],
                         ids=['a-page', 'an-object', 'a-null-entry', 'a-null-uri', 'no-uri'])
def test_list_when_rspamd_answers_something_else(client, rspamd, maps):
    """A proxy's sign-in page, or JSON that is not Rspamd's map list, is reported as
    an error in the list, not as maps that are not loaded."""
    rspamd['maps'] = maps
    r = client.get('/api/rspamd/maps')
    assert r.status_code == 200
    assert r.json()['error'] and r.json()['configured'] is True


# ---------------------------------------------------------------- one map

def test_map_content(client):
    r = client.get(f'/api/rspamd/maps/{MAP}')
    assert r.status_code == 200
    body = r.json()
    assert body['entry_count'] == 1 and body['metadata']['filename'] == MAP
    assert body['content_hash'] == content_hash(body['content'])


def test_map_not_loaded_in_rspamd(client):
    r = client.get(f'/api/rspamd/maps/{OTHER}')
    assert r.status_code == 200
    assert r.json()['content'] == '' and r.json()['entry_count'] == 0 and 'message' in r.json()


def test_map_errors(client, rspamd, monkeypatch):
    assert client.get('/api/rspamd/maps/nope.map').status_code == 404
    rspamd['getmap'] = REFUSED
    assert client.get(f'/api/rspamd/maps/{MAP}').status_code == 502
    for maps in (NOT_JSON, [None]):
        rspamd['maps'] = maps
        assert client.get(f'/api/rspamd/maps/{MAP}').status_code == 502
    monkeypatch.setattr(settings._inner, 'rspamd_password', None)
    assert client.get(f'/api/rspamd/maps/{MAP}').status_code == 400


# ---------------------------------------------------------------- saving a map

def test_save(client, rspamd):
    opened = client.get(f'/api/rspamd/maps/{MAP}').json()
    r = client.put(f'/api/rspamd/maps/{MAP}', json={'content': opened['content'] + 'b@example.org\n',
                                                   'base_hash': opened['content_hash']})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['normalized_entries'] == 1 and body['content_hash'] == content_hash(rspamd['content'])
    assert body['api_response'] == rspamd['edit']


def test_save_that_cannot_be_read_back(client, rspamd):
    rspamd['getmap'] = REFUSED
    r = client.put(f'/api/rspamd/maps/{MAP}', json={'content': '/^c@example\\.com$/i'})
    assert r.status_code == 200, r.text
    assert r.json()['content_hash'] is None and r.json()['entry_count'] == 1


def test_a_save_read_back_as_a_page_is_still_saved(client, rspamd):
    """Without base_hash the map is written first; a page in place of the map list
    when it is read back does not make the save look failed."""
    rspamd['maps'] = NOT_JSON
    r = client.put(f'/api/rspamd/maps/{MAP}', json={'content': '/^d@example\\.com$/i'})
    assert r.status_code == 200, r.text
    assert r.json()['content_hash'] is None and rspamd['writes'] == ['/^d@example\\.com$/i']


def test_save_errors(client, rspamd, monkeypatch):
    assert client.put('/api/rspamd/maps/nope.map', json={'content': ''}).status_code == 404
    assert client.put(f'/api/rspamd/maps/{MAP}', json={}).status_code == 422

    invalid = client.put(f'/api/rspamd/maps/{MAP}', json={'content': '/[unclosed/'})
    assert invalid.status_code == 400
    assert invalid.json()['detail']['validation_errors'][0]['line'] == 1

    changed = client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x', 'base_hash': content_hash('old')})
    assert changed.status_code == 409 and changed.json()['detail']['code'] == 'map_changed'

    rspamd['edit'] = [{'type': 'danger', 'msg': ['map_content_empty']}]
    assert client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x'}).status_code == 502
    # mailcow says its reply is JSON, and it is not: the mailcow client tries the write three times
    # and does not catch it (500)
    rspamd['edit'] = httpx.Response(200, text='<html>', headers={'content-type': 'application/json'})
    assert client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x'}).status_code == 500

    # The map it is checked against cannot be read: nothing is written
    rspamd['maps'] = NOT_JSON
    assert client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x', 'base_hash': 'h'}).status_code == 502
    for line in (HUGE_REPEAT, DEEP_NESTING):
        refused = client.put(f'/api/rspamd/maps/{MAP}', json={'content': f'# c\n{line}'})
        assert refused.status_code == 400
        assert refused.json()['detail']['validation_errors'][0]['line'] == 2

    monkeypatch.setattr(mailcow_api, 'headers_rw', None)
    assert client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x'}).status_code == 403
    assert rspamd['writes'] == ['x'] * 4


def test_save_while_another_save_runs(client, rspamd, monkeypatch):
    monkeypatch.setattr(rspamd_map_lock, 'WAIT_SECONDS', 0.05)
    assert rspamd_map_lock._LOCK.acquire(timeout=5)
    try:
        r = client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x'})
    finally:
        rspamd_map_lock._LOCK.release()
    assert r.status_code == 409
    assert isinstance(r.json()['detail'], str)
    assert rspamd['writes'] == []


# ---------------------------------------------------------------- checking content

def test_validate(client):
    r = client.post('/api/rspamd/validate', json={'content': '# c\n/[unclosed/\nuser@example.com\nexample.org'})
    assert r.status_code == 200
    body = r.json()
    assert body['valid'] is False and body['entry_count'] == 3
    assert [f['severity'] for f in body['errors']] == ['error']
    assert [f['severity'] for f in body['warnings']] == ['warning']


@pytest.mark.parametrize('line', [HUGE_REPEAT, DEEP_NESTING], ids=['huge-repeat', 'deep-nesting'])
def test_validate_a_pattern_that_cannot_be_checked(client, line):
    r = client.post('/api/rspamd/validate', json={'content': f'# c\n{line}'})
    assert r.status_code == 200
    body = r.json()
    assert body['valid'] is False and body['errors'][0]['line'] == 2
    assert body['errors'][0]['error'].startswith('Pattern cannot be checked')


def test_validate_errors(client):
    assert client.post('/api/rspamd/validate', json={'filename': MAP}).status_code == 422
