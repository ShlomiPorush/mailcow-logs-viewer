"""Raw log collection is separate from the Logs page: the services other pages
read from the raw log table (Dovecot for message details and the breach alert,
Ratelimited for Rate Limits, SOGo for Devices) keep being collected and kept
when the Logs page is off or the service is unticked there."""
import asyncio
import hashlib
from datetime import datetime

import pytest

from app import raw_logs_worker
from app.config import settings


@pytest.fixture()
def logs_page_off(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', 'logs')
    monkeypatch.setattr(settings._inner, 'raw_logs_enabled', True)
    monkeypatch.setattr(settings._inner, 'raw_logs_services', 'postfix,dovecot')


def test_with_the_logs_page_off_only_what_other_pages_read_is_collected(logs_page_off):
    assert settings.raw_logs_collected_list == ['dovecot', 'ratelimited', 'sogo']


def test_turning_raw_log_collection_off_keeps_what_other_pages_read(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'raw_logs_enabled', False)
    assert settings.raw_logs_collected_list == ['dovecot', 'ratelimited', 'sogo']


def test_the_logs_page_selection_is_collected_with_what_other_pages_read(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'raw_logs_enabled', True)
    monkeypatch.setattr(settings._inner, 'raw_logs_services', 'postfix,acme')
    assert settings.raw_logs_collected_list == ['postfix', 'acme', 'dovecot', 'ratelimited', 'sogo']


def test_a_page_turned_off_stops_needing_its_service(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', 'logs,rate-limits,devices,netfilter')
    assert settings.raw_logs_collected_list == ['dovecot']
    assert settings.raw_logs_required == {'dovecot': ['Message details (Sieve and delivery results)']}


def test_sieve_results_and_the_breach_alert_work_with_the_logs_page_off(logs_page_off):
    from app import scheduler
    assert scheduler.dovecot_correlation_available() is True


def test_the_worker_fetches_them_with_the_logs_page_off_and_streams_none(logs_page_off, monkeypatch):
    fetched, streamed = [], []

    async def collect(service, page_size):
        fetched.append(service)
        return ([{'time': '1', 'message': 'x'}], [], 1, None)

    async def broadcast(service, entries):
        streamed.append(service)
    monkeypatch.setattr(raw_logs_worker, '_collect_service', collect)
    monkeypatch.setattr(raw_logs_worker, '_ws_broadcast_fn', broadcast)
    monkeypatch.setattr(raw_logs_worker, '_ws_broadcast_all_fn', None)
    monkeypatch.setattr(raw_logs_worker, '_unavailable_services', set())
    asyncio.run(raw_logs_worker.fetch_raw_service_logs())
    assert fetched == ['dovecot', 'ratelimited', 'sogo']
    assert streamed == []


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def test_turning_the_logs_page_off_keeps_the_rows_other_pages_read(logs_page_off):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import SessionLocal, init_db
    from app.models import RawServiceLog
    init_db()
    db = SessionLocal()
    marker = 'raw-collection-test'

    def cleanup():
        db.query(RawServiceLog).filter(RawServiceLog.raw_data['message'].astext.like(f'%{marker}%')).delete(synchronize_session=False)
        db.commit()
    cleanup()
    try:
        for service in ('postfix', 'acme', 'dovecot', 'ratelimited', 'sogo'):
            entry = {'time': '1', 'message': f'{marker} {service}'}
            db.add(RawServiceLog(service=service, time=datetime.utcnow(), raw_data=entry,
                                 message_hash=hashlib.sha256(repr(entry).encode()).hexdigest()))
        db.commit()
        raw_logs_worker.delete_uncollected_raw_logs(db)
        db.commit()
        kept = {s for (s,) in db.query(RawServiceLog.service).filter(
            RawServiceLog.raw_data['message'].astext.like(f'%{marker}%'))}
        assert kept == {'dovecot', 'ratelimited', 'sogo'}
    finally:
        cleanup()
        db.close()
