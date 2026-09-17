"""Exercise the actual CSV downloads with untrusted text and typed values."""
import csv
import io
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.database import get_db

ROUTES = [
    ("/api/export/postfix/csv", "message", "Message"),
    ("/api/export/rspamd/csv", "subject", "Subject"),
    ("/api/export/netfilter/csv", "message", "Message"),
    ("/api/export/messages/csv", "subject", "Subject"),
    ("/api/suppressions/export", "notes", "notes"),
]


@pytest.fixture
def export_client(monkeypatch):
    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)
    row = SimpleNamespace(**{key: "ordinary" for key in (
        "program priority queue_id message_id sender recipient status relay dsn message "
        "subject sender_smtp action direction user ip username auth_method rule_id "
        "final_status type reason source notes".split()
    )})
    row.email = "user@example.com"
    row.time = row.first_seen = row.last_seen = row.created_at = datetime(2026, 1, 1)
    row.delay = row.score = -1.5
    row.required_score = 5.0
    row.attempts_left = row.size = row.bounce_count = row.hard_bounce_count = row.soft_bounce_count = 2
    row.is_spam = row.has_auth = row.is_complete = row.active = True
    row.recipients_smtp = ["user@example.com"]
    row.symbols = {"TEST": {}}
    row.expires_at = row.rspamd_log_id = None
    query = Mock()
    query.filter.return_value = query.order_by.return_value = query.limit.return_value = query
    query.all.return_value = [row]
    query.first.return_value = None
    db = Mock()
    db.query.return_value = query
    app.dependency_overrides[get_db] = lambda: db
    try:
        yield TestClient(app), row, db, query
    finally:
        app.dependency_overrides.pop(get_db, None)


def download(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=" in response.headers["content-disposition"]
    return list(csv.DictReader(io.StringIO(response.text)))


@pytest.mark.parametrize("path,attribute,column", ROUTES)
@pytest.mark.parametrize("text", ["=1+1", "+1+1", "-1+1", "@SUM(1)", " \t=1+1", "\r=1+1", "\n=1+1", "\x00=1+1", "\x1f=1+1", "\x7f=1+1", "\u200b=1+1", "\ufeff=1+1", "\uff1d1+1", "\uff0b1+1", "\uff0d1+1", "\uff20SUM(1)"])
def test_all_downloads_escape_formula_text(export_client, path, attribute, column, text):
    client, row, db, _ = export_client
    setattr(row, attribute, text)
    assert download(client, path)[0][column] == "'" + text
    assert getattr(row, attribute) == text
    db.commit.assert_not_called()


@pytest.mark.parametrize("path,attribute,column", ROUTES)
@pytest.mark.parametrize("text", ["ordinary", "'literal", 'text, "quote"\nnext line', 'text\",=1+1', "", None])
def test_safe_text_and_csv_boundaries_are_preserved(export_client, path, attribute, column, text):
    client, row, _, _ = export_client
    setattr(row, attribute, text)
    records = download(client, path)
    assert len(records) == 1
    assert None not in records[0]
    assert records[0][column] == (text or "")


def test_negative_numbers_and_booleans_remain_typed_values(export_client):
    client, _, _, _ = export_client
    record = download(client, "/api/export/rspamd/csv")[0]
    assert record["Score"] == "-1.5"
    assert record["Size"] == "2"
    assert record["Is Spam"] == "True"

@pytest.mark.parametrize("email,notes", [
    ("=user@example.com", "=1+1"),
    ("+user@example.com", " \t=1+1\n"),
    ("'user@example.com", "'=literal"),
    ("user@example.com", 'ordinary, "quoted"\ntext'),
])
def test_suppression_export_import_preserves_addresses_and_notes(export_client, email, notes):
    client, row, db, _ = export_client
    row.email, row.notes, row.type, row.reason = email, notes, "email", "manual"
    response = client.get("/api/suppressions/export")
    exported = list(csv.DictReader(io.StringIO(response.text)))[0]
    assert "_csv_escape_v1" in exported
    result = client.post("/api/suppressions/import", files={"file": ("roundtrip.csv", response.content)})
    assert result.status_code == 200
    assert result.json() == {"imported": 1, "skipped": 0, "errors": []}
    saved = db.add.call_args.args[0]
    assert saved.email == email
    assert saved.notes == notes
    assert saved.type == "email"
    assert saved.reason == "manual"
    assert saved.source == "import"
    assert saved.synced_to_rspamd is False


@pytest.mark.parametrize("text,notes", [
    ("email,type,reason,notes\nuser@example.com,email,manual,ordinary\n", "ordinary"),
    ("user@example.com,email,manual,ordinary\n", "ordinary"),
    ("email,type,reason,source,notes\nuser@example.com,email,manual,manual,original notes\n", "original notes"),
    ("email,type,reason,notes\nuser@example.com,email,manual,'=literal\n", "'=literal"),
])
def test_legacy_suppression_imports_do_not_unescape_unmarked_text(export_client, text, notes):
    client, _, db, _ = export_client
    result = client.post("/api/suppressions/import", files={"file": ("legacy.csv", text)})
    assert result.json()["imported"] == 1
    assert db.add.call_args.args[0].notes == notes


def test_invalid_escape_metadata_is_rejected(export_client):
    client, _, db, _ = export_client
    text = "email,type,reason,notes,_csv_escape_v1\nuser@example.com,email,manual,ordinary,notes\n"
    result = client.post("/api/suppressions/import", files={"file": ("invalid.csv", text)})
    assert result.json()["imported"] == 0
    assert result.json()["errors"] == ["Row 2: invalid CSV escape metadata"]
    db.add.assert_not_called()


def test_empty_suppression_export_retains_headers(export_client):
    client, _, _, query = export_client
    query.all.return_value = []
    response = client.get("/api/suppressions/export")
    reader = csv.DictReader(io.StringIO(response.text))
    assert reader.fieldnames[0] == "email"
    assert reader.fieldnames[-1] == "_csv_escape_v1"
    assert list(reader) == []


@pytest.mark.parametrize("path,attribute,column", ROUTES[:4])
def test_empty_log_exports_keep_the_existing_404(export_client, path, attribute, column):
    client, _, _, query = export_client
    query.all.return_value = []
    assert client.get(path).status_code == 404
