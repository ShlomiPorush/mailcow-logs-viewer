"""Needs attention lists alerts of three areas: Security (sign-in and sending
alerts, the protection rules), Domains (DNS changes) and DMARC & TLS (report
import errors). Each person sees the alerts of the areas they may view, and a
dismissal, Dismiss all and Undo change only those of the areas they may act in.
"""
import uuid
from datetime import datetime

import pytest

from test_users import _add, _admin, _person, _sign_in, people, stored  # noqa: F401  (fixtures)

MARK = uuid.uuid4().hex[:8]
TYPES = ('volume_spike', 'protection_breach', 'dns_change', 'dmarc_import_failed')
AREA_TYPES = {'security': {'volume_spike', 'auth_failure_burst', 'smtp_abuse_block', 'protection_breach',
                           'protection_ban_failed'},
              'domains': {'dns_change'}, 'dmarc': {'dmarc_import_failed'}}
LIST = '/api/security-alerts'


def _alert(stored, alert_type, severity='warning'):
    from app.models import SecurityAlert
    return stored(SecurityAlert(alert_type=alert_type, severity=severity, subject=f'{MARK}.example.com',
                                title=f'{alert_type} {MARK}', created_at=datetime.utcnow())).id


@pytest.fixture
def alerts(people, stored):
    """One open alert of each kind, the protection one critical, by type."""
    return {t: _alert(stored, t, 'critical' if t == 'protection_breach' else 'warning') for t in TYPES}


def _open(ids):
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        return sorted(r.id for r in db.query(SecurityAlert).filter(
            SecurityAlert.id.in_(list(ids)), SecurityAlert.acknowledged == False))  # noqa: E712


def _counts(types):
    """What the database holds open for these types: (count, critical)."""
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        rows = db.query(SecurityAlert.severity).filter(SecurityAlert.alert_type.in_(list(types)),
                                                       SecurityAlert.acknowledged == False).all()  # noqa: E712
        return len(rows), sum(1 for r in rows if r[0] == 'critical')


def _list(client):
    r = client.get(LIST, params={'acknowledged': 'false', 'limit': 500})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize('views, readable', [
    (('domains',), {'domains'}),
    (('dmarc',), {'dmarc'}),
    (('security',), {'security'}),
    (('domains', 'dmarc'), {'domains', 'dmarc'}),
    (('messages',), set()),
])
def test_each_person_sees_the_alerts_of_the_areas_they_may_view(alerts, views, readable):
    """Before this, the list was Security's: a person with only Domains got a refusal."""
    body = _list(_person(_admin(), 'viewer-' + '-'.join(views), views=views))
    types = set().union(*(AREA_TYPES[a] for a in readable)) if readable else set()
    mine = {i for t, i in alerts.items() if t in types}
    listed = {a['id'] for a in body['alerts']}
    assert mine <= listed and not (set(alerts.values()) - mine) & listed
    assert {a['alert_type'] for a in body['alerts']} <= types
    # The counts and ids follow the same areas, also the critical one they cannot see
    assert set(body['unacknowledged_ids']) & set(alerts.values()) == mine
    assert (body['unacknowledged_count'], body['unacknowledged_critical']) == _counts(types)
    # View only: nothing to dismiss
    assert body['writable_ids'] == []


def test_an_admin_sees_and_may_dismiss_every_alert(alerts):
    body = _list(_admin())
    assert set(alerts.values()) <= {a['id'] for a in body['alerts']}
    assert set(alerts.values()) <= set(body['writable_ids'])


def test_the_dismissable_ids_are_those_of_the_areas_the_person_may_act_in(alerts):
    body = _list(_person(_admin(), 'mixed', views=('security', 'dmarc'), acts=('domains',)))
    assert set(body['unacknowledged_ids']) & set(alerts.values()) == set(alerts.values())
    assert set(body['writable_ids']) & set(alerts.values()) == {alerts['dns_change']}
    assert set(body['writable_ids']) <= set(body['unacknowledged_ids'])


def test_the_dismissable_ids_go_past_the_rows_asked_for(people, stored):
    ids = [_alert(stored, 'dns_change') for _ in range(3)]
    body = _person(_admin(), 'domains-act', acts=('domains',)).get(LIST, params={'acknowledged': 'false', 'limit': 1}).json()
    assert len(body['alerts']) == 1 and set(ids) <= set(body['writable_ids'])


def test_new_alerts_are_listed_with_anomaly_detection_off(alerts, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'anomaly_detection_enabled', False)
    body = _list(_person(_admin(), 'domains-view', views=('domains',)))
    assert body['enabled'] is False and alerts['dns_change'] in {a['id'] for a in body['alerts']}


def test_one_alert_is_dismissed_only_in_an_area_the_person_may_act_in(alerts):
    admin = _admin()
    person = _person(admin, 'domains-act', views=('security',), acts=('domains',))
    # Another area's, seen but not to be changed: refused
    r = person.post(f"{LIST}/{alerts['volume_spike']}/acknowledge")
    assert r.status_code == 403 and r.json() == {'detail': 'You do not have permission for this.'}
    # An area not even seen: as if it were not there
    assert person.post(f"{LIST}/{alerts['dmarc_import_failed']}/acknowledge").status_code == 404
    assert _open(alerts.values()) == sorted(alerts.values())
    done = person.post(f"{LIST}/{alerts['dns_change']}/acknowledge").json()
    assert done['ids'] == [alerts['dns_change']] and done['receipt']
    assert person.post(f"/api/security-alerts/acknowledgements/{done['receipt']}/undo").json()['ids'] == [alerts['dns_change']]


def test_a_person_who_may_only_view_cannot_dismiss_at_all(alerts):
    person = _person(_admin(), 'all-view', views=('security', 'domains', 'dmarc'))
    for method, path in (('POST', f"{LIST}/{alerts['dns_change']}/acknowledge"), ('POST', f'{LIST}/acknowledge-all'),
                         ('POST', f'/api/security-alerts/acknowledgements/{uuid.uuid4()}/undo')):
        r = person.request(method, path)
        assert r.status_code == 403, (path, r.text)
    assert _open(alerts.values()) == sorted(alerts.values())


def test_dismiss_all_leaves_the_alerts_of_other_areas_open_with_ids_or_without(alerts):
    person = _person(_admin(), 'dmarc-act', views=('security', 'domains'), acts=('dmarc',))
    # Ids it was never given, of areas it may only view, are left as they are
    done = person.post(f'{LIST}/acknowledge-all', json={'ids': list(alerts.values())}).json()
    assert done['ids'] == [alerts['dmarc_import_failed']] and done['acknowledged'] == 1
    person.post(f"/api/security-alerts/acknowledgements/{done['receipt']}/undo")
    # No body: every open alert, of its areas only
    done = person.post(f'{LIST}/acknowledge-all').json()
    assert alerts['dmarc_import_failed'] in done['ids']
    assert not set(done['ids']) & {alerts['volume_spike'], alerts['protection_breach'], alerts['dns_change']}
    assert _open(alerts.values()) == sorted(i for t, i in alerts.items() if t != 'dmarc_import_failed')


def test_undo_reopens_only_what_the_person_may_act_in_and_keeps_the_rest_for_someone_who_may(alerts):
    from app.database import get_db_context
    from app.models import SecurityAlert
    admin = _admin()
    receipt = admin.post(f'{LIST}/acknowledge-all', json={'ids': list(alerts.values())}).json()['receipt']
    person = _person(admin, 'domains-act', acts=('domains',))
    undone = person.post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()
    assert undone['ids'] == [alerts['dns_change']] and undone['restored'] == 1
    with get_db_context() as db:
        kept = db.query(SecurityAlert).filter(SecurityAlert.id.in_(list(alerts.values()))).all()
        assert {a.id for a in kept if a.acknowledged and str(a.ack_batch) == receipt} == set(alerts.values()) - {alerts['dns_change']}
    # The same receipt still undoes the rest for an admin
    assert admin.post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()['restored'] == 3
    assert _open(alerts.values()) == sorted(alerts.values())


def test_undo_after_the_persons_access_changed_reopens_nothing(alerts):
    from test_users import _change
    admin = _admin()
    row = _add(admin, 'changing', access='custom', views=('domains',), acts=('domains', 'security'))
    receipt = _sign_in('changing').post(f"{LIST}/{alerts['dns_change']}/acknowledge").json()['receipt']
    assert _change(admin, row, acts=['security']).status_code == 200
    undone = _sign_in('changing').post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()
    assert undone['restored'] == 0
    assert alerts['dns_change'] not in _open(alerts.values())


@pytest.mark.parametrize('alert_type', ['dns_change', 'dmarc_import_failed', 'protection_breach'])
def test_only_sign_in_and_sending_alerts_have_activity(alerts, alert_type):
    admin = _admin()
    assert admin.get(f'{LIST}/{alerts[alert_type]}/activity').status_code == 404
    # A Security viewer cannot read another area's alert through it
    security = _person(admin, 'security-view-' + alert_type.replace('_', '-'), views=('security',))
    assert security.get(f'{LIST}/{alerts[alert_type]}/activity').status_code == 404


def test_the_policy_needs_one_of_the_three_areas_to_dismiss():
    from app import user_access
    from app.agent_access import scopes
    for path in ('/api/security-alerts/{alert_id}/acknowledge', '/api/security-alerts/acknowledge-all',
                 '/api/security-alerts/acknowledgements/{receipt}/undo'):
        rule = scopes.POLICY[('POST', path)]
        assert rule.kind == scopes.WRITE
        need = user_access.need_for('POST', path)
        assert need.kind == user_access.ANY_AREA
        assert set(need.areas) == {('security', 'write'), ('domains', 'write'), ('dmarc', 'write')}
        for area in ('security', 'domains', 'dmarc'):
            assert scopes.allows(frozenset({f'{area}:write'}), rule)
        assert not scopes.allows(frozenset({'security:read', 'domains:read', 'dmarc:read', 'messages:write'}), rule)
    assert user_access.need_for('GET', '/api/security-alerts').kind == user_access.SIGNED_IN
    # Nothing else became a write anyone may make
    assert not scopes.allows(frozenset(), scopes.Rule(scopes.ANY, scopes.WRITE))


# ---------- past 10,000 open alerts ----------

MANY = 10001
MANY_SUBJECT = f'many-{MARK}.example.com'


@pytest.fixture
def many(people):
    """10,001 open alerts of Security, the newest of all, and 10,001 of Domains just before them."""
    from sqlalchemy import text
    from app.database import get_db_context

    def wipe():
        with get_db_context() as db:
            db.execute(text('DELETE FROM security_alerts WHERE subject = :s'), {'s': MANY_SUBJECT})
    wipe()
    with get_db_context() as db:
        for alert_type, days in (('volume_spike', 2), ('dns_change', 1)):
            db.execute(text(
                "INSERT INTO security_alerts (alert_type, severity, subject, title, acknowledged, created_at) "
                "SELECT :t, 'warning', :s, :t, false, (now() at time zone 'utc') + make_interval(days => :d, secs => g) "
                "FROM generate_series(1, :n) AS g"), {'t': alert_type, 's': MANY_SUBJECT, 'd': days, 'n': MANY})
        rows = db.execute(text('SELECT id, alert_type FROM security_alerts WHERE subject = :s'), {'s': MANY_SUBJECT}).all()
    yield {t: {i for i, kind in rows if kind == t} for t in ('volume_spike', 'dns_change')}
    wipe()


def test_past_10000_open_alerts_each_list_of_ids_has_its_own_cap(many):
    from app.routers.security_alerts import MAX_ACK_IDS
    person = _person(_admin(), 'many-mixed', views=('security',), acts=('domains',))
    body = person.get(LIST, params={'acknowledged': 'false', 'limit': 1}).json()
    # The count goes past the cap: it is counted, not taken from the ids
    assert (body['unacknowledged_count'], body['unacknowledged_critical']) == _counts(AREA_TYPES['security'] | AREA_TYPES['domains'])
    assert body['unacknowledged_count'] > 2 * MAX_ACK_IDS
    # The newest open alerts the person sees are the Security ones, which they may only view
    assert len(body['unacknowledged_ids']) == MAX_ACK_IDS and set(body['unacknowledged_ids']) <= many['volume_spike']
    # What they may dismiss lies past those, under a cap of its own
    assert len(body['writable_ids']) == MAX_ACK_IDS and set(body['writable_ids']) <= many['dns_change']
    assert not set(body['writable_ids']) & set(body['unacknowledged_ids'])
    newest = sorted(many['dns_change'], reverse=True)[:MAX_ACK_IDS]
    assert sorted(body['writable_ids'], reverse=True) == newest
    # Dismiss all with them changes exactly those
    done = person.post(f'{LIST}/acknowledge-all', json={'ids': body['writable_ids']}).json()
    assert done['acknowledged'] == MAX_ACK_IDS
    assert len(_open(many['dns_change'])) == 1 and len(_open(many['volume_spike'])) == MANY


def test_past_10000_open_alerts_an_admin_gets_both_lists_capped(many):
    from app.routers.security_alerts import MAX_ACK_IDS
    body = _admin().get(LIST, params={'acknowledged': 'false', 'limit': 1}).json()
    assert len(body['unacknowledged_ids']) == MAX_ACK_IDS and len(body['writable_ids']) == MAX_ACK_IDS
    assert body['unacknowledged_ids'] == body['writable_ids']
    assert body['unacknowledged_count'] >= 2 * MANY


# ---------- a type that belongs to no area ----------

def test_an_alert_type_of_no_area_is_an_admins_only(people, stored):
    unknown = _alert(stored, 'future_kind', 'critical')
    admin = _admin()
    # Every area, View and Take action, but not an admin
    person = _person(admin, 'everything', views=('security', 'domains', 'dmarc', 'messages'),
                     acts=('security', 'domains', 'dmarc'))
    body = _list(person)
    assert unknown not in {a['id'] for a in body['alerts']}
    assert unknown not in body['unacknowledged_ids'] and unknown not in body['writable_ids']
    assert (body['unacknowledged_count'], body['unacknowledged_critical']) == _counts(
        AREA_TYPES['security'] | AREA_TYPES['domains'] | AREA_TYPES['dmarc'])
    assert person.post(f'{LIST}/{unknown}/acknowledge').status_code == 404
    assert person.post(f'{LIST}/acknowledge-all', json={'ids': [unknown]}).json()['acknowledged'] == 0
    assert unknown not in person.post(f'{LIST}/acknowledge-all').json()['ids']
    assert _open([unknown]) == [unknown]
    # An admin sees it, and dismisses it; the person cannot undo that
    body = _list(admin)
    assert unknown in {a['id'] for a in body['alerts']} and unknown in body['writable_ids']
    receipt = admin.post(f'{LIST}/{unknown}/acknowledge').json()['receipt']
    assert person.post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()['restored'] == 0
    assert _open([unknown]) == []
    assert admin.post(f'/api/security-alerts/acknowledgements/{receipt}/undo').json()['ids'] == [unknown]
