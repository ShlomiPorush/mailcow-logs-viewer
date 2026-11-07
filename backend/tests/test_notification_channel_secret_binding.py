"""A masked channel secret is not restored when the channel points at another server.

The channel API returns secrets masked. Saving with the mask keeps the stored
token, which is right while the destination is the same; with a changed
server_url / url it would send the stored token to the new server.
"""
import types

import pytest
from fastapi import HTTPException

from app.routers import notifications as nr
from app.services import notification_channels as nc

MASK = nc.MASK

STORED = {
    "ntfy": {"server_url": "https://ntfy.example.com", "topic": "alerts", "token": "tk_Dummy_Secret_5"},
    "gotify": {"server_url": "https://gotify.example.com", "app_token": "Dummy-Gotify-Token"},
    "webhook": {"url": "https://hooks.example.com/in", "auth_header": "Bearer Dummy-Hook-Token"},
}
SECRET = {"ntfy": "token", "gotify": "app_token", "webhook": "auth_header"}
ENDPOINT = {"ntfy": "server_url", "gotify": "server_url", "webhook": "url"}


@pytest.mark.parametrize("ctype", sorted(STORED))
def test_masked_secret_with_a_moved_server_is_refused(ctype):
    incoming = {**STORED[ctype], ENDPOINT[ctype]: "https://collector.example.net", SECRET[ctype]: MASK}
    with pytest.raises(nc.SecretEndpointChanged) as exc:
        nc.merge_config(ctype, STORED[ctype], incoming)
    assert "again" in str(exc.value)


@pytest.mark.parametrize("ctype", sorted(STORED))
def test_masked_secret_with_the_same_server_is_kept(ctype):
    incoming = {**STORED[ctype], ENDPOINT[ctype]: STORED[ctype][ENDPOINT[ctype]] + "/", SECRET[ctype]: MASK}
    merged = nc.merge_config(ctype, STORED[ctype], incoming)
    assert merged[SECRET[ctype]] == STORED[ctype][SECRET[ctype]]


@pytest.mark.parametrize("ctype", sorted(STORED))
def test_new_secret_with_a_moved_server_is_saved(ctype):
    incoming = {**STORED[ctype], ENDPOINT[ctype]: "https://collector.example.net", SECRET[ctype]: "Dummy-New"}
    assert nc.merge_config(ctype, STORED[ctype], incoming)[SECRET[ctype]] == "Dummy-New"


def test_ntfy_empty_server_means_the_default_server():
    stored = {"server_url": "", "topic": "alerts", "token": "tk_Dummy"}
    incoming = {"server_url": "https://ntfy.sh", "topic": "alerts", "token": MASK}
    assert nc.merge_config("ntfy", stored, incoming)["token"] == "tk_Dummy"


def test_update_channel_answers_with_the_message():
    row = types.SimpleNamespace(id=1, name="alerts", channel_type="ntfy", config=dict(STORED["ntfy"]),
                                alert_types=None, enabled=True, last_success_at=None,
                                last_error=None, last_error_at=None, created_at=None)
    query = types.SimpleNamespace(filter=lambda *a: types.SimpleNamespace(first=lambda: row))
    db = types.SimpleNamespace(query=lambda *a: query, commit=lambda: None, refresh=lambda r: None,
                               rollback=lambda: None)
    request = nr.ChannelRequest(name="alerts", channel_type="ntfy", config={
        "server_url": "https://collector.example.net", "topic": "alerts", "token": MASK})
    with pytest.raises(HTTPException) as exc:
        nr.update_channel(1, request, db)
    assert exc.value.status_code == 422
    assert "access token" in exc.value.detail.lower()
    assert row.config == STORED["ntfy"]
