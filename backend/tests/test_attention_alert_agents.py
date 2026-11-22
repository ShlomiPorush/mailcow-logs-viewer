"""Agents and the Needs attention alerts of three areas (Security, Domains,
DMARC & TLS): an agent lists the alerts of the areas its connection may view,
and dismisses or undoes only with Take action in the alert's own area. The
three changes stay actions: read_api refuses them, perform_action runs them.
"""
import json
import uuid
from datetime import datetime

import pytest

from test_agent_access import _connect, _tool, live_agents  # noqa: F401  (live_agents is a fixture)
from test_agent_device_rest import _api, _connect_with_code

MARK = uuid.uuid4().hex[:8]
TYPES = ('volume_spike', 'dns_change', 'dmarc_import_failed')


@pytest.fixture
def alerts(live_agents):
    from app.database import get_db_context
    from app.models import SecurityAlert
    ids = {}
    with get_db_context() as db:
        for t in TYPES:
            row = SecurityAlert(alert_type=t, severity='warning', subject=f'{MARK}.example.com', title=f'{t} {MARK}',
                                created_at=datetime.utcnow())
            db.add(row)
            db.flush()
            ids[t] = row.id
    yield ids
    with get_db_context() as db:
        db.query(SecurityAlert).filter(SecurityAlert.id.in_(list(ids.values()))).delete(synchronize_session=False)


def _answer(result):
    head, _, body = result['content'][0]['text'].partition('\n')
    return head, json.loads(body) if body.startswith('{') else body


def test_an_agent_lists_the_alerts_of_the_areas_it_may_view(alerts):
    client, _, tokens = _connect(views=('domains',))
    head, body = _answer(_tool(client, tokens['access_token'], 'read_api', {'path': '/api/security-alerts',
                                                                          'query': {'limit': 500}}))
    assert head.startswith('HTTP 200')
    assert {a['alert_type'] for a in body['alerts']} <= {'dns_change'}
    assert alerts['dns_change'] in {a['id'] for a in body['alerts']}
    assert body['writable_ids'] == []
    # An area outside the three: an empty list, not a refusal
    client, _, tokens = _connect(views=('messages',))
    head, body = _answer(_tool(client, tokens['access_token'], 'read_api', {'path': '/api/security-alerts'}))
    assert head.startswith('HTTP 200') and body['alerts'] == [] and body['unacknowledged_count'] == 0


def test_read_api_never_runs_a_dismissal(alerts):
    client, _, tokens = _connect(views=('domains',), acts=('domains',))
    token = tokens['access_token']
    for path in (f"/api/security-alerts/{alerts['dns_change']}/acknowledge", '/api/security-alerts/acknowledge-all',
                 f'/api/security-alerts/acknowledgements/{uuid.uuid4()}/undo'):
        result = _tool(client, token, 'read_api', {'method': 'POST', 'path': path})
        assert result['isError'] and 'perform_action' in result['content'][0]['text'], path
    assert _open(alerts) == set(alerts.values())


@pytest.mark.parametrize('area, alert_type', [('security', 'volume_spike'), ('domains', 'dns_change'),
                                              ('dmarc', 'dmarc_import_failed')])
def test_perform_action_dismisses_in_the_area_the_agent_may_act_in(alerts, area, alert_type):
    client, _, tokens = _connect(views=('security', 'domains', 'dmarc'), acts=(area,))
    token = tokens['access_token']
    head, body = _answer(_tool(client, token, 'perform_action', {
        'method': 'POST', 'path': '/api/security-alerts/acknowledge-all', 'body': {'ids': list(alerts.values())}}))
    assert head.startswith('HTTP 200') and body['ids'] == [alerts[alert_type]]
    others = [i for t, i in alerts.items() if t != alert_type]
    head, _ = _answer(_tool(client, token, 'perform_action', {
        'method': 'POST', 'path': f'/api/security-alerts/{others[0]}/acknowledge'}))
    assert head.startswith('HTTP 403')
    head, body = _answer(_tool(client, token, 'perform_action', {
        'method': 'POST', 'path': f"/api/security-alerts/acknowledgements/{body['receipt']}/undo"}))
    assert body['ids'] == [alerts[alert_type]]


def test_view_only_and_other_areas_cannot_dismiss(alerts):
    client, _, tokens = _connect(views=('security', 'domains', 'dmarc'), acts=('quarantine',))
    result = _tool(client, tokens['access_token'], 'perform_action', {
        'method': 'POST', 'path': '/api/security-alerts/acknowledge-all', 'body': {'ids': list(alerts.values())}})
    text = result['content'][0]['text']
    assert result['isError'] and 'Security, Domains or DMARC & TLS' in text and 'domains:write' in text
    assert _open(alerts) == set(alerts.values())


def test_a_bearer_call_follows_the_same_areas(alerts):
    agent, _, tokens = _connect_with_code(views=('dmarc',), acts=('dmarc',))
    token = tokens['access_token']
    r = _api(agent, token, 'POST', f"/api/security-alerts/{alerts['dns_change']}/acknowledge")
    assert r.status_code == 404
    r = _api(agent, token, 'POST', f"/api/security-alerts/{alerts['dmarc_import_failed']}/acknowledge")
    assert r.status_code == 200 and r.json()['ids'] == [alerts['dmarc_import_failed']]
    assert _open(alerts) == {alerts['volume_spike'], alerts['dns_change']}
    agent, _, tokens = _connect_with_code(views=('dmarc',))
    assert _api(agent, tokens['access_token'], 'POST', '/api/security-alerts/acknowledge-all').status_code == 403


def test_an_agent_cannot_read_another_areas_alert_through_its_activity(alerts):
    client, _, tokens = _connect(views=('security',))
    for t in ('dns_change', 'dmarc_import_failed'):
        head, _ = _answer(_tool(client, tokens['access_token'], 'read_api',
                                {'path': f'/api/security-alerts/{alerts[t]}/activity'}))
        assert head.startswith('HTTP 404'), t


def test_list_endpoints_shows_the_dismissals_under_each_area_the_agent_acts_in(live_agents):
    client, _, tokens = _connect(views=('dmarc', 'domains'), acts=('domains',))
    token = tokens['access_token']

    def listed(area=None):
        text = _tool(client, token, 'list_endpoints', {'area': area} if area else {})['content'][0]['text']
        return {(e['method'], e['path']): e for e in json.loads(text)['endpoints']}
    ack = ('POST', '/api/security-alerts/acknowledge-all')
    assert listed('domains')[ack]['kind'] == 'act' and listed('domains')[ack]['area'] == 'domains'
    assert ack not in listed('dmarc') and ack not in listed('security')
    assert listed()[ack]['area'] == 'domains'
    assert listed()[('GET', '/api/security-alerts')]['kind'] == 'read'


def test_an_agent_with_every_area_never_gets_an_alert_type_of_no_area(live_agents):
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        row = SecurityAlert(alert_type='future_kind', severity='critical', subject=f'{MARK}.example.com',
                            title=f'future {MARK}', created_at=datetime.utcnow())
        db.add(row)
        db.flush()
        unknown = {'future_kind': row.id}
    try:
        client, _, tokens = _connect(views=('security', 'domains', 'dmarc'), acts=('security', 'domains', 'dmarc'))
        token = tokens['access_token']
        head, body = _answer(_tool(client, token, 'read_api', {'path': '/api/security-alerts', 'query': {'limit': 500}}))
        assert head.startswith('HTTP 200')
        assert unknown['future_kind'] not in {a['id'] for a in body['alerts']}
        assert unknown['future_kind'] not in body['unacknowledged_ids'] + body['writable_ids']
        head, _ = _answer(_tool(client, token, 'perform_action', {
            'method': 'POST', 'path': f"/api/security-alerts/{unknown['future_kind']}/acknowledge"}))
        assert head.startswith('HTTP 404')
        head, body = _answer(_tool(client, token, 'perform_action', {
            'method': 'POST', 'path': '/api/security-alerts/acknowledge-all', 'body': {'ids': [unknown['future_kind']]}}))
        assert body['acknowledged'] == 0
        head, body = _answer(_tool(client, token, 'perform_action', {
            'method': 'POST', 'path': '/api/security-alerts/acknowledge-all'}))
        assert unknown['future_kind'] not in body['ids']
        assert _open(unknown) == {unknown['future_kind']}
        # A dismissal made by an admin is not the agent's to undo
        receipt = client.post(f"/api/security-alerts/{unknown['future_kind']}/acknowledge").json()['receipt']
        head, body = _answer(_tool(client, token, 'perform_action', {
            'method': 'POST', 'path': f'/api/security-alerts/acknowledgements/{receipt}/undo'}))
        assert body['restored'] == 0 and _open(unknown) == set()
    finally:
        with get_db_context() as db:
            db.query(SecurityAlert).filter(SecurityAlert.id == unknown['future_kind']).delete(synchronize_session=False)


def _open(alerts):
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        return {r.id for r in db.query(SecurityAlert).filter(SecurityAlert.id.in_(list(alerts.values())),
                                                             SecurityAlert.acknowledged == False)}  # noqa: E712
