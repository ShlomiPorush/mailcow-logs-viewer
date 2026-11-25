import asyncio
import re

import pytest

from app import scheduler
from app.mailcow_api import MailcowAPI

ROWS = [{'unix_time': n} for n in range(1, 501)]


def _mailcow(monkeypatch, rows):
    async def request(self, endpoint, method='GET', **kwargs):
        service, spec = re.match(r'^/api/v1/get/logs/([a-z-]+)/(.+)$', endpoint).groups()
        if '-' not in spec:
            return rows[:int(spec)] or {}
        first, last = (int(part) for part in spec.split('-'))
        if first < 1 or last < first:
            return {}
        base = 0 if service == 'rspamd-history' else 1
        return rows[first - base:last - base + 1] or {}
    monkeypatch.setattr(MailcowAPI, '_make_request', request)


@pytest.mark.parametrize('service', ['rspamd', 'postfix'])
def test_the_pages_of_a_log_hold_every_row_once(monkeypatch, service):
    _mailcow(monkeypatch, ROWS)
    api = MailcowAPI()
    read = api.get_rspamd_logs_page if service == 'rspamd' else api.get_postfix_logs_page
    seen, offset = [], 0
    while True:
        page = asyncio.run(read(page_size=100, offset=offset))
        if not page:
            break
        seen += page
        offset += len(page)
    assert seen == ROWS


@pytest.mark.parametrize('count', [1, 2, 100, 101])
def test_the_rspamd_history_is_counted_to_its_last_row(monkeypatch, count):
    _mailcow(monkeypatch, ROWS[:count])
    scheduler._log_count_cache.clear()
    try:
        assert asyncio.run(scheduler._discover_total_logs('rspamd-history')) == count
        assert asyncio.run(scheduler._discover_total_logs('postfix')) == count
    finally:
        scheduler._log_count_cache.clear()
