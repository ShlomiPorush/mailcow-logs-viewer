import io
import json
import mmap
import os
import queue
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest
import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from test_dovecot_correlation import (  # noqa: E402,F401
    _add_correlation, _add_raw_line, _get_correlation, _lmtp, _msgid, env,
)

BACKEND = Path(__file__).resolve().parent.parent
INSTANCE = Path(__file__).resolve().parent / "instance_process.py"
TAKEOVER_SECONDS = 20


class Instance:
    def __init__(self, lock_path: Path, **env):
        self.process = subprocess.Popen(
            [sys.executable, str(INSTANCE), str(lock_path)], cwd=BACKEND, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, **env})
        self.answers = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        assert self._next(120) == "up"

    def _read(self):
        for line in self.process.stdout:
            if line.startswith("@@"):
                self.answers.put(json.loads(line[2:]))

    def _next(self, timeout: float):
        try:
            return self.answers.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(f"the instance did not answer within {timeout} s") from None

    def ask(self, command: str):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self._next(30)

    def wait_for(self, condition) -> dict:
        deadline = time.monotonic() + TAKEOVER_SECONDS
        while True:
            status = self.ask("status")
            if condition(status) or time.monotonic() > deadline:
                return status
            time.sleep(0.5)

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.write("exit\n")
            self.process.stdin.flush()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()


def _system_settings() -> dict:
    from app.database import get_db_context
    from app.models import SystemSetting
    with get_db_context() as db:
        return {row.key: row.value for row in db.query(SystemSetting).all()}


def _restore_system_settings(before: dict) -> None:
    from app.database import get_db_context
    from app.models import SystemSetting
    with get_db_context() as db:
        db.query(SystemSetting).filter(SystemSetting.key.notin_(list(before))).delete(synchronize_session=False)
        for row in db.query(SystemSetting).filter(SystemSetting.key.in_(list(before))).all():
            row.value = before[row.key]


@pytest.fixture
def instances(app_schema, tmp_path):
    started = []
    before = _system_settings()

    def start(**env):
        instance = Instance(tmp_path / "shared-data-leader.lock", **env)
        started.append(instance)
        return instance

    yield start
    for instance in started:
        instance.stop()
    _restore_system_settings(before)


def _leads(status: dict) -> bool:
    return status["scheduler"]


def test_only_one_instance_runs_the_background_jobs_until_it_stops(instances):
    first = instances()
    second = instances()

    assert _leads(first.ask("status"))
    assert not _leads(second.ask("status"))

    first.stop()
    assert _leads(second.wait_for(_leads))


def test_a_settings_save_on_the_waiting_instance_starts_no_collector_there(instances):
    first = instances()
    second = instances()

    assert second.ask("collect")["raw_logs"] is False

    first.stop()
    assert second.wait_for(lambda status: status["raw_logs"])["raw_logs"]


def test_the_waiting_instance_takes_over_with_the_settings_saved_meanwhile(instances):
    from app.database import get_db_context
    from app.services.settings_store import save_config_overrides_to_db

    first = instances(SETTINGS_EDIT_VIA_UI_ENABLED="true")
    second = instances(SETTINGS_EDIT_VIA_UI_ENABLED="true")
    saved = second.ask("status")["fetch_interval"] + 17
    with get_db_context() as db:
        save_config_overrides_to_db(db, {"fetch_interval": saved})

    first.stop()
    assert second.wait_for(_leads)["fetch_interval"] == saved


def test_the_second_instance_starts_without_touching_rows_or_waiting_for_table_locks(instances):
    from app.database import engine, get_db_context
    from app.models import MessageCorrelation

    first = instances()
    message_id = _msgid()
    for _ in range(2):
        _add_correlation(message_id, queue_id="TWOINST1")

    writer = engine.connect()
    held = writer.begin()
    writer.execute(text("LOCK TABLE postfix_logs, rspamd_logs, message_correlations IN ROW EXCLUSIVE MODE"))
    try:
        started = time.monotonic()
        instances()
        assert time.monotonic() - started < 60
    finally:
        held.rollback()
        writer.close()
        with get_db_context() as db:
            remaining = db.query(MessageCorrelation).filter(MessageCorrelation.message_id == message_id)
            count = remaining.count()
            remaining.delete(synchronize_session=False)
    assert count == 2
    assert _leads(first.ask("status"))


def _in_new_process(code: str) -> str:
    finished = subprocess.run([sys.executable, "-c", code], cwd=BACKEND, capture_output=True, text=True,
                              timeout=120, env=os.environ.copy())
    assert finished.returncode == 0, finished.stderr[-2000:]
    return finished.stdout


def test_the_next_leader_continues_the_import_where_the_previous_one_stopped(app_schema):
    try:
        _in_new_process("from app import scheduler; scheduler._resume_offset['postfix'] = 400")
        answer = _in_new_process("from app import scheduler; print(scheduler._resume_offset['postfix'])")
        assert answer.strip().splitlines()[-1] == "400"
    finally:
        _in_new_process("from app import scheduler; scheduler._resume_offset['postfix'] = 0")


DOVECOT_RUN = (
    "import asyncio\n"
    "from app import scheduler\n"
    "scheduler.dovecot_correlation_available = lambda: True\n"
    "asyncio.run(scheduler.correlate_dovecot_logs())\n"
    "assert scheduler.job_status['correlate_dovecot']['status'] == 'success', scheduler.job_status\n"
)


def test_a_dovecot_verdict_waiting_for_its_message_survives_a_change_of_leader(env):
    msgid = _msgid()
    _add_raw_line(_lmtp(f'sieve: msgid=<{msgid}>: discarded message'))
    _in_new_process(DOVECOT_RUN)

    key = _add_correlation(msgid, final_status='delivered')
    _in_new_process(DOVECOT_RUN)

    assert _get_correlation(key).dovecot_status == 'discarded'


@pytest.mark.parametrize("path", [
    "/api/settings/jobs/fetch_logs/run",
    "/api/settings/geoip/download",
    "/api/system/summary/email?force=true",
    "/api/dmarc/imap/sync",
    "/api/blacklist/check",
    "/api/suppressions/sync",
])
def test_a_job_started_by_hand_waits_for_the_instance_that_runs_the_background_jobs(path):
    from app import leader
    from app.main import app
    leader._lock_file.close()
    leader._lock_file = None
    assert TestClient(app).post(path).status_code == 503


def _tar_with(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(f"GeoLite2-City_20261126/{name}")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class _Download:
    status_code = 200

    def __init__(self, body: bytes):
        self.body = body
        self.headers = {"content-length": str(len(body))}

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass


def test_a_geoip_update_leaves_a_reader_of_the_old_file_intact(monkeypatch, tmp_path):
    from app.services import geoip_downloader

    path = tmp_path / "GeoLite2-City.mmdb"
    path.write_bytes(b"old" * 4096)
    monkeypatch.setitem(geoip_downloader.DATABASES["City"], "path", str(path))
    monkeypatch.setattr(geoip_downloader, "get_maxmind_license_key", lambda: "key")
    monkeypatch.setattr(geoip_downloader, "get_maxmind_account_id", lambda: "account")
    monkeypatch.setattr(geoip_downloader.requests, "get",
                        lambda *args, **kwargs: _Download(_tar_with("GeoLite2-City.mmdb", b"new" * 4096)))

    with open(path, "rb") as reader, mmap.mmap(reader.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        assert geoip_downloader.download_single_database("City")
        assert mapped[:3] == b"old"
    assert path.read_bytes()[:3] == b"new"
