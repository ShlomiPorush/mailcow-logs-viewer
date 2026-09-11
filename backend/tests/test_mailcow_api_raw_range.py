"""MailcowAPI.get_raw_logs_range: endpoint shape, error normalisation, and the
{} answer mailcow gives past the end of a list. No database, no network."""
import asyncio

import pytest
from tenacity import RetryError

from app.mailcow_api import MailcowAPI, MailcowAPIError


def _client():
    return MailcowAPI()


def test_requests_the_inclusive_range_for_the_offset(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='GET', **kw):
        seen['endpoint'] = endpoint
        return [{'time': '1'}]
    monkeypatch.setattr(api, '_make_request', fake)

    out = asyncio.run(api.get_raw_logs_range('postfix', offset=100, page_size=100))
    assert seen['endpoint'] == '/api/v1/get/logs/postfix/100-199'
    assert out == [{'time': '1'}]


def test_an_empty_dict_past_the_end_becomes_an_empty_list(monkeypatch):
    api = _client()

    async def fake(endpoint, method='GET', **kw):
        return {}
    monkeypatch.setattr(api, '_make_request', fake)
    assert asyncio.run(api.get_raw_logs_range('rspamd-history', 5000, 500)) == []


def test_retry_error_is_normalised_to_mailcow_api_error(monkeypatch):
    """_make_request's retry decorator has no reraise, so after three failures
    tenacity raises RetryError; callers must only ever see MailcowAPIError."""
    api = _client()

    class _Attempt:
        def exception(self):
            return MailcowAPIError('connection refused')

    async def fake(endpoint, method='GET', **kw):
        raise RetryError(_Attempt())
    monkeypatch.setattr(api, '_make_request', fake)

    with pytest.raises(MailcowAPIError) as exc:
        asyncio.run(api.get_raw_logs_range('postfix', 1, 10))
    assert 'connection refused' in str(exc.value)


def test_rejects_bad_arguments():
    api = _client()
    with pytest.raises(ValueError):
        asyncio.run(api.get_raw_logs_range('not-a-service', 1, 10))
    with pytest.raises(ValueError):
        asyncio.run(api.get_raw_logs_range('postfix', 0, 10))
    with pytest.raises(ValueError):
        asyncio.run(api.get_raw_logs_range('postfix', 1, 0))
