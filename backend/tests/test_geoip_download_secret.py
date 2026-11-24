import logging
import secrets

import pytest
import requests

from app.services import geoip_downloader as gd

KEY = secrets.token_hex(16)
ACCOUNT = "123456"


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(gd, "get_maxmind_license_key", lambda: KEY)
    monkeypatch.setattr(gd, "get_maxmind_account_id", lambda: ACCOUNT)
    monkeypatch.setattr(gd, "GEOIP_DB_DIR", str(tmp_path))
    calls = []

    def fail_like_requests(url, **kwargs):
        calls.append((url, kwargs))
        prepared = requests.Request("GET", url, params=kwargs.get("params")).prepare()
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='download.maxmind.com', port=443): "
            f"Max retries exceeded with url: {prepared.path_url} "
            f"(Caused by NewConnectionError('Failed to establish a new connection'))"
        )

    monkeypatch.setattr(gd.requests, "get", fail_like_requests)
    return calls


def test_network_error_does_not_log_the_license_key(configured, caplog):
    with caplog.at_level(logging.DEBUG):
        assert gd.download_single_database("ASN") is False
    assert "Network error downloading ASN database" in caplog.text
    assert KEY not in caplog.text


def test_license_key_is_not_sent_in_the_url(configured, caplog):
    gd.download_single_database("City")
    (url, kwargs), = configured
    prepared = requests.Request("GET", url, params=kwargs.get("params")).prepare()
    assert KEY not in prepared.url
    assert kwargs.get("auth") == (ACCOUNT, KEY)
    assert "GeoLite2-City" in prepared.url


def test_error_text_that_quotes_the_key_is_redacted(monkeypatch, caplog, tmp_path):
    monkeypatch.setattr(gd, "get_maxmind_license_key", lambda: KEY)
    monkeypatch.setattr(gd, "get_maxmind_account_id", lambda: ACCOUNT)

    def boom(url, **kwargs):
        raise RuntimeError(f"unexpected failure for key {KEY}")

    monkeypatch.setattr(gd.requests, "get", boom)
    with caplog.at_level(logging.DEBUG):
        assert gd.download_single_database("City") is False
    assert "Error downloading City database" in caplog.text
    assert KEY not in caplog.text


def test_rejected_account_id_falls_back_without_logging_the_key(configured, monkeypatch, caplog):
    fail_like_requests = gd.requests.get

    class Rejected:
        status_code = 401

        def close(self):
            pass

    def first_rejected(url, **kwargs):
        if kwargs.get("auth"):
            configured.append((url, kwargs))
            return Rejected()
        return fail_like_requests(url, **kwargs)

    monkeypatch.setattr(gd.requests, "get", first_rejected)
    with caplog.at_level(logging.DEBUG):
        assert gd.download_single_database("ASN") is False
    assert len(configured) == 2
    assert "license_key" in configured[1][1]["params"]
    assert "Network error downloading ASN database" in caplog.text
    assert KEY not in caplog.text
