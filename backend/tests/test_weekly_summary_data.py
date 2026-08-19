"""Issue #81: the weekly summary crashed with
"object dict can't be used in 'await' expression".

get_monitored_hosts() became a plain function in v2.7.0 but
reporting.get_system_summary_data() still awaited it, so every weekly
summary (scheduled or on demand) failed before sending anything.
"""
import ast
import asyncio
import inspect
import pathlib

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.routers import reporting  # noqa: E402


def test_every_awaited_helper_in_reporting_is_a_coroutine_function():
    """Structural guard: any name reporting.py awaits directly must be async.
    A helper that is turned into a sync function (as in #81) fails here with
    a message naming it, without needing a database."""
    source = pathlib.Path(reporting.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    awaited_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name):
                awaited_names.add(func.id)
    assert awaited_names, "expected reporting.py to await at least one helper"

    wrong = []
    for name in sorted(awaited_names):
        obj = getattr(reporting, name, None)
        if obj is None:
            continue  # imported inside a function body; not resolvable here
        if not inspect.iscoroutinefunction(obj):
            wrong.append(name)
    assert not wrong, f"reporting.py awaits non-async helpers: {wrong}"


def test_system_summary_data_builds_with_sync_blacklist_helper(monkeypatch):
    """Behavioural guard: the summary aggregates the blacklist section from
    the sync get_monitored_hosts() result instead of crashing."""
    async def fake_mailbox_summary(date_range, db):
        return {"total_messages": 1}

    async def fake_mailcow_info():
        return {"domains": {"active": 1, "total": 1}}

    async def fake_storage():
        return {"used": "1G"}

    def fake_monitored_hosts():
        return {"hosts": [
            {"host": "mail.example.com", "status": "listed"},
            {"host": "relay.example.com", "status": "clean"},
        ]}

    async def fake_all_mailbox_stats(**kwargs):
        return {"mailboxes": [{"username": "a@example.com", "combined_failed": 3}]}

    async def fake_domains(db):
        return {"domains": []}

    async def fake_list():
        return []

    monkeypatch.setattr(reporting, "get_mailbox_stats_summary", fake_mailbox_summary)
    monkeypatch.setattr(reporting, "get_mailcow_info", fake_mailcow_info)
    monkeypatch.setattr(reporting, "get_storage_status", fake_storage)
    monkeypatch.setattr(reporting, "get_monitored_hosts", fake_monitored_hosts)
    monkeypatch.setattr(reporting, "get_all_mailbox_stats", fake_all_mailbox_stats)
    monkeypatch.setattr(reporting, "get_all_domains_with_dns", fake_domains)

    from app import mailcow_api as mailcow_api_module
    monkeypatch.setattr(mailcow_api_module.mailcow_api, "get_queue", fake_list)
    monkeypatch.setattr(mailcow_api_module.mailcow_api, "get_quarantine", fake_list)

    data = asyncio.run(reporting.get_system_summary_data(db=None))

    assert data["blacklist"]["status"] == "listed"
    assert data["blacklist"]["listed_count"] == 1
    assert data["blacklist"]["total_hosts"] == 2
    assert data["top_failures"][0]["username"] == "a@example.com"
