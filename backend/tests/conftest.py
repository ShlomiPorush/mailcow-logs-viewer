import os
import pathlib
import secrets
import sys
import time as _real_time

import pytest

os.environ.setdefault("MAILCOW_URL", "https://mail.example.com")
os.environ.setdefault("MAILCOW_API_KEY", secrets.token_hex(16))
os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", secrets.token_hex(16))
os.environ.setdefault("POSTGRES_DB", "test")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


def registered_routes(application):
    from fastapi.routing import _iter_routes_with_context

    for original, context in _iter_routes_with_context(application.routes):
        route = original if context is None else (context.starlette_route or context)
        assert getattr(route, "path", None) is not None, type(route)
        yield route


class _ModuleClock:
    def __init__(self):
        self._overrides = {}

    def __getattr__(self, name):
        overrides = self.__dict__.get("_overrides", {})
        if name in overrides:
            return overrides[name]
        return getattr(_real_time, name)


@pytest.fixture
def module_clock(monkeypatch):
    clocks = {}

    def apply(module, **overrides):
        clock = clocks.get(module)
        if clock is None:
            clock = clocks[module] = _ModuleClock()
            monkeypatch.setattr(module, "time", clock)
        clock._overrides.update(overrides)

    return apply


@pytest.fixture
def app_schema():
    from sqlalchemy import text
    from app.database import engine, init_db
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    init_db()


@pytest.fixture(autouse=True)
def leader_lock_in_a_temporary_directory(monkeypatch, tmp_path):
    from app import leader
    monkeypatch.setattr(leader, "LOCK_PATH", str(tmp_path / "leader.lock"))
    leader.try_lead()
    yield
    if leader._lock_file is not None:
        leader._lock_file.close()
        leader._lock_file = None


@pytest.fixture(autouse=True)
def local_domains_loaded(monkeypatch):
    from app import config
    from app.mailcow_api import mailcow_api
    monkeypatch.setattr(config, "_cached_domains_complete", mailcow_api.base_url)


@pytest.fixture(autouse=True)
def queue_log_unread(monkeypatch, request):
    scheduler = sys.modules.get("app.scheduler")
    if scheduler is not None and "real_queue_log" not in request.fixturenames:
        monkeypatch.setattr(scheduler, "_logged_deferral_codes", lambda arrived, waiting: {})


@pytest.fixture
def real_queue_log():
    pass


@pytest.fixture(autouse=True)
def mailcow_reachable(monkeypatch):
    from app import mailcow_api as client
    monkeypatch.setattr(client.mailcow_api, "_reachability", client._Reachability())


_contracts = {}


@pytest.fixture(autouse=True)
def api_contract(monkeypatch, request):
    marker = request.node.get_closest_marker("no_contract")
    if marker is not None:
        if not marker.kwargs.get("reason"):
            pytest.fail("no_contract needs reason=: say which code the test stubs")
        return
    from starlette.testclient import TestClient

    original = TestClient.request

    def checked_request(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        main = sys.modules.get("app.main")
        if main is not None and self.app is main.app:
            from contract import Contract, check_response
            contract = _contracts.get(id(main.app))
            if contract is None or contract.app is not main.app:
                contract = _contracts[id(main.app)] = Contract(main.app)
            for answer in (*response.history, response):
                check_response(contract, answer)
        return response

    monkeypatch.setattr(TestClient, "request", checked_request)
