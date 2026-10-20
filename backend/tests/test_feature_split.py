"""Spam Filter's one switch became two: Suppressions (Outbound) and Rspamd
(the maps, a page of its own). The old name spam-filter, in ENV, in a stored value or in
a save, still means both, so a switch that was off never turns on by itself.
"""
from types import SimpleNamespace

import pytest

from app.config import settings, normalize_disabled_features, FEATURE_IDS


def test_the_old_name_stands_for_both_features():
    assert normalize_disabled_features('spam-filter') == ['suppressions', 'rspamd']
    assert normalize_disabled_features(' Spam-Filter , queue,spam-filter,suppressions') == \
        ['suppressions', 'rspamd', 'queue']
    assert normalize_disabled_features(['queue', 'SPAM-FILTER']) == ['queue', 'suppressions', 'rspamd']
    assert normalize_disabled_features('') == [] and normalize_disabled_features(None) == []
    assert normalize_disabled_features('rspamd') == ['rspamd']
    assert 'spam-filter' not in FEATURE_IDS


@pytest.mark.parametrize('value, suppressions_on, maps_on', [
    ('spam-filter', False, False),
    ('suppressions', False, True),
    ('rspamd', True, False),
    ('', True, True),
])
def test_what_each_value_turns_off(monkeypatch, value, suppressions_on, maps_on):
    monkeypatch.setattr(settings._inner, 'disabled_features', value)
    assert settings.is_feature_enabled('suppressions') is suppressions_on
    assert settings.is_feature_enabled('rspamd') is maps_on
    assert settings.is_feature_enabled('queue') and settings.is_feature_enabled('quarantine')


def test_a_name_no_switch_has_is_an_error_not_on(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', 'spam-filter')
    with pytest.raises(ValueError):
        settings.is_feature_enabled('spam-filter')


def test_info_lists_the_features_an_old_name_stands_for(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'disabled_features', 'spam-filter,devices')
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, '__init__', lambda s, *a, **k: orig(s, *a, **{**k, 'check_dir': False}))
    from fastapi.testclient import TestClient
    from app.main import app
    body = TestClient(app).get('/api/info').json()
    assert body['disabled_features'] == ['devices', 'rspamd', 'suppressions']


def test_the_settings_form_shows_the_features_an_old_name_stands_for(monkeypatch):
    from app.routers.settings import _effective_config_for_editable
    monkeypatch.setattr(settings._inner, 'disabled_features', 'spam-filter, queue')
    config = _effective_config_for_editable(settings._inner)
    assert config['disabled_features'] == 'suppressions,rspamd,queue'


def _save(monkeypatch, body, stored=None):
    """update_settings with the DB replaced by a dict; returns what was stored
    and the transitions the save named."""
    import app.services.settings_store as ss
    from app.routers import settings as rs
    from app import config as cfg
    data = dict(stored or {})
    monkeypatch.setenv('SETTINGS_EDIT_VIA_UI_ENABLED', 'true')
    monkeypatch.delenv('DISABLED_FEATURES', raising=False)

    def overrides(db, types_):
        return {k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()}
    monkeypatch.setattr(ss, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'get_config_overrides_from_db', overrides)
    monkeypatch.setattr(rs, 'save_config_overrides_to_db', lambda db, ov: data.update(ov))
    monkeypatch.setattr(rs, 'has_config_overrides_in_db', lambda db: bool(data))
    monkeypatch.setattr(rs, 'cleanup_disabled_feature_data', lambda db: {})
    monkeypatch.setattr(rs, 'run_feature_data_sweep_soon', lambda: None)
    monkeypatch.setattr(rs, 'reschedule_interval_jobs', lambda: None)
    monkeypatch.setattr(rs, 'mailcow_api', SimpleNamespace(reload_config=lambda: None, has_rw_key=False))
    monkeypatch.setattr(rs, 'oauth2_client', SimpleNamespace(reload_config=lambda: None))
    seen = []
    monkeypatch.setattr(rs, '_record_list_transition',
                        lambda db, was, now, switched=False: seen.append((was, now, switched)) or None)
    monkeypatch.setattr(rs, 'clear_maxmind_validation_status', lambda db: None)
    cfg.reload_settings(object())
    try:
        result = rs.update_settings(body, db=object())
        state = (settings.is_feature_enabled('suppressions'), settings.is_feature_enabled('rspamd'))
    finally:
        monkeypatch.undo()
        cfg.reload_settings()
    return data, seen, result, state


def test_a_save_stores_the_new_names_only(monkeypatch):
    data, _, result, state = _save(monkeypatch, {'disabled_features': 'spam-filter,queue'})
    assert data['disabled_features'] == 'suppressions,rspamd,queue'
    assert state == (False, False)


def test_a_save_rejects_a_name_no_switch_has(monkeypatch):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        _save(monkeypatch, {'disabled_features': 'spam-filters'})
    assert error.value.status_code == 400


def test_an_old_stored_value_rewritten_to_its_new_names_is_no_transition(monkeypatch):
    """The form of a stored spam-filter shows both switches off; saving it
    unchanged stores the new names and changes nothing for the list."""
    data, seen, _, state = _save(monkeypatch, {'disabled_features': 'suppressions,rspamd'},
                                 stored={'disabled_features': 'spam-filter'})
    assert data['disabled_features'] == 'suppressions,rspamd'
    assert state == (False, False)
    assert seen == [(False, False, False)]


def test_turning_the_maps_on_leaves_the_list_alone(monkeypatch):
    """Maps on, Suppressions still off: not a switch of the list."""
    data, seen, _, state = _save(monkeypatch, {'disabled_features': 'suppressions'},
                                 stored={'disabled_features': 'spam-filter'})
    assert state == (False, True)
    assert seen == [(False, False, False)]


def test_turning_the_maps_off_leaves_the_list_alone(monkeypatch):
    data, seen, _, state = _save(monkeypatch, {'disabled_features': 'rspamd'})
    assert state == (True, False)
    assert len(seen) == 1 and seen[0][2] is False and seen[0][0] == seen[0][1]


def test_the_old_name_is_read_only_where_it_is_accepted():
    """A leftover 'spam-filter' would ask for a switch nobody has."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / 'app'
    found = {}
    for path in root.rglob('*.py'):
        uses = re.findall(r"""['"]spam-filter['"]""", path.read_text(encoding='utf-8'))
        if uses:
            found[path.relative_to(root).as_posix()] = len(uses)
    # The alias table, and the old name the purge endpoint still takes
    assert found == {'config.py': 1, 'routers/settings.py': 1}
