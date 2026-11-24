import hashlib
import secrets

import pytest

MAP = 'global_rcpt_blacklist.map'


class FakeMaps:
    has_rw_key = True

    def __init__(self, content):
        self.content = content
        self.writes = []
        self.read_fails = False

    async def find_rspamd_map_id(self, filename):
        return 7 if filename == MAP else None

    async def get_rspamd_map_content(self, map_id):
        from app.mailcow_api import MailcowAPIError
        if self.read_fails:
            raise MailcowAPIError('getmap timed out')
        return self.content

    async def edit_rspamd_map(self, filename, data):
        self.writes.append(data)
        self.content = data.strip() + '\n'
        self.read_fails = self.read_fails_after_write
        return [{'type': 'success'}]

    read_fails_after_write = False


@pytest.fixture
def maps(monkeypatch):
    from app.config import settings
    from app.routers import rspamd_maps
    fake = FakeMaps('/^a@example\\.com$/i\n')
    monkeypatch.setattr(rspamd_maps, 'mailcow_api', fake)
    monkeypatch.setattr(settings._inner, 'rspamd_password', secrets.token_hex(16))
    return fake


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_a_save_from_a_copy_read_before_a_change_is_refused(maps, client):
    opened = client.get(f'/api/rspamd/maps/{MAP}').json()
    maps.content = opened['content'] + '/^b@example\\.com$/i\n'

    saved = client.put(f'/api/rspamd/maps/{MAP}', json={
        'content': opened['content'] + '/^c@example\\.com$/i', 'base_hash': _sha(opened['content'])})

    assert saved.status_code == 409, saved.text
    assert saved.json()['detail']['code'] == 'map_changed'
    assert maps.writes == []
    assert 'b@example' in maps.content


def test_the_answer_holds_the_map_as_saved_and_the_next_save_goes_through(maps, client):
    opened = client.get(f'/api/rspamd/maps/{MAP}').json()
    assert opened['content_hash'] == _sha(opened['content'])

    first = client.put(f'/api/rspamd/maps/{MAP}', json={
        'content': '/^c@example\\.com$/i\n\n', 'base_hash': opened['content_hash']})
    assert first.status_code == 200, first.text
    assert first.json()['content'] == maps.content
    assert first.json()['content_hash'] == _sha(maps.content)

    second = client.put(f'/api/rspamd/maps/{MAP}', json={
        'content': '/^d@example\\.com$/i', 'base_hash': first.json()['content_hash']})
    assert second.status_code == 200, second.text


def test_a_saved_map_that_cannot_be_read_back_has_no_hash(maps, client):
    opened = client.get(f'/api/rspamd/maps/{MAP}').json()
    maps.read_fails_after_write = True
    saved = client.put(f'/api/rspamd/maps/{MAP}', json={'content': 'x', 'base_hash': opened['content_hash']})
    assert saved.status_code == 200, saved.text
    assert saved.json()['content_hash'] is None
    assert maps.writes == ['x']
