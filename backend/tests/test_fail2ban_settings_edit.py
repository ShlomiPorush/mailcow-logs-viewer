"""POST /api/fail2ban changes the Fail2ban settings and never the lists.

mailcow's Fail2ban edit replaces the whole object. A caller that read it with
GET /api/fail2ban and saved it back later used to write its old denylist over
a ban a protection rule wrote in between, while the app kept showing the
address as banned. The lists are now read fresh under the lock; lists sent
with the settings must be the current ones. Every write goes to a fake mailcow.
"""
import pytest

from test_protection_enforce import FakeMailcow, _enforce, _trap_hit
from test_protection_rules import TRAP_IP, db  # noqa: F401  (db is a fixture)


class WholeObjectMailcow(FakeMailcow):
    """Saves every attribute it is sent, the way mailcow's edit does."""

    async def edit_fail2ban(self, attrs):
        self.edits.append(attrs)
        self.settings.update(attrs)
        return [{'type': 'success', 'msg': 'saved'}]


@pytest.fixture
def api(monkeypatch):
    from app.routers import logs
    api = WholeObjectMailcow(blacklist='192.0.2.200/32', whitelist='203.0.113.0/24')
    api.settings['manage_external'] = 1
    monkeypatch.setattr(logs, 'mailcow_api', api)
    return api


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_a_ban_written_between_read_and_save_survives_the_save(db, api, client):
    held = client.get('/api/fail2ban').json()
    _trap_hit(db)
    _enforce(api)
    assert f'{TRAP_IP}/32' in api.black()

    saved = client.post('/api/fail2ban', json={'attr': {**held, 'max_attempts': 6}})

    assert saved.status_code == 409, saved.text
    assert saved.json()['detail']['code'] == 'lists_changed'
    assert api.black() == ['192.0.2.200/32', f'{TRAP_IP}/32']
    assert str(api.settings['max_attempts']) == '7', 'nothing was saved'


def test_settings_sent_without_the_lists_keep_the_current_lists(db, api, client):
    saved = client.post('/api/fail2ban', json={'attr': {'max_attempts': '6', 'ban_time': '7200'}})

    assert saved.status_code == 200, saved.text
    edit = api.edits[-1]
    assert (edit['max_attempts'], edit['ban_time']) == ('6', '7200')
    assert (edit['blacklist'], edit['whitelist']) == ('192.0.2.200/32', '203.0.113.0/24')
    assert edit['manage_external'] == '1', 'a setting left out keeps its value'
    assert 'legacy_entries' not in edit


def test_the_current_object_saves_its_settings(db, api, client):
    held = client.get('/api/fail2ban').json()
    saved = client.post('/api/fail2ban', json={'attr': {**held, 'max_attempts': 6}})
    assert saved.status_code == 200, saved.text
    assert api.settings['max_attempts'] == '6'
    assert api.black() == ['192.0.2.200/32']
