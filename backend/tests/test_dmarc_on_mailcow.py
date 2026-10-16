"""The DMARC & TLS page says which domains are not on this mailcow server (issue #412).

A domain removed from mailcow keeps its reports for history; the domains list and
the domain overview carry on_mailcow so the page can mark it. While the server's
domains are not known (before the first domain sync) every domain is None, never
False, so no domain is marked by mistake. The database is stubbed at the route's
helpers, so these run without PostgreSQL.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app import config
from app.routers import dmarc as dmarc_router

HOSTED, ALIAS, GONE = 'hosted.example.com', 'alias.example.com', 'removed.example.com'


def _entry(domain):
    return {'domain': domain, 'stats_30d': {'total_messages': 0}}


@pytest.fixture()
def active_domains():
    """Set the cached mailcow domains through the real config cache, and restore it."""
    previous = config._cached_active_domains

    def set_to(domains):
        config._cached_active_domains = domains
    yield set_to
    config._cached_active_domains = previous


@pytest.fixture()
def client(monkeypatch):
    from app.main import app
    cached = {}

    def build():
        return {'domains': [_entry(HOSTED), _entry('Alias.Example.COM.'), _entry(GONE)], 'total': 3, 'daily': []}, {}

    async def no_lookup(domain, dmarc_check=None, tls_check=None):
        return None, None
    monkeypatch.setattr(dmarc_router, '_cached_domains_list', lambda key: cached.get(key))
    monkeypatch.setattr(dmarc_router, 'set_dmarc_cache', lambda key, value: cached.__setitem__(key, value))
    monkeypatch.setattr(dmarc_router, '_build_domains_list', build)
    monkeypatch.setattr(dmarc_router, '_live_record_checks', no_lookup)
    monkeypatch.setattr(dmarc_router, '_load_overview_dns', lambda domain: ({}, {}))
    monkeypatch.setattr(dmarc_router, '_load_domain_overview',
                        lambda domain, days, dmarc, tls: {'domain': domain, 'totals': {'total_messages': 0}})
    return TestClient(app)


def _flags(client):
    return {d['domain']: d['on_mailcow'] for d in client.get('/api/dmarc/domains').json()['domains']}


def test_a_domain_on_the_server_and_one_that_is_not(client, active_domains):
    active_domains([HOSTED, ALIAS])
    flags = _flags(client)
    assert flags[HOSTED] is True
    assert flags[GONE] is False


def test_the_match_ignores_case_and_a_trailing_dot(client, active_domains):
    active_domains(['HOSTED.example.com', 'alias.example.com'])
    flags = _flags(client)
    assert flags[HOSTED] is True
    assert flags['Alias.Example.COM.'] is True


@pytest.mark.parametrize('cached', [None, []])
def test_unknown_server_domains_mark_nothing(client, active_domains, cached):
    active_domains(cached)
    assert set(_flags(client).values()) == {None}


def test_a_cached_list_follows_the_current_server_domains(client, active_domains):
    active_domains(None)
    assert set(_flags(client).values()) == {None}
    # The domain sync ran after the list was cached: the cached list shows it at once
    active_domains([HOSTED])
    flags = _flags(client)
    assert flags[HOSTED] is True and flags[GONE] is False


def test_the_overview_says_it_too(client, active_domains):
    active_domains([HOSTED])
    assert client.get(f'/api/dmarc/domains/{HOSTED}/overview').json()['on_mailcow'] is True
    assert client.get(f'/api/dmarc/domains/{GONE}/overview').json()['on_mailcow'] is False
    active_domains([])
    assert client.get(f'/api/dmarc/domains/{GONE}/overview').json()['on_mailcow'] is None
