"""DMARC and TLS detail endpoints: a missing day or sender is 404, a malformed date 400."""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import dmarc


@pytest.fixture
def client():
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = []
    db.query.return_value.join.return_value.filter.return_value.all.return_value = []
    app = FastAPI()
    app.include_router(dmarc.router)
    app.dependency_overrides[dmarc.get_db] = lambda: db
    return TestClient(app)


@pytest.mark.parametrize("path", [
    "/dmarc/domains/example.com/reports/2001-01-01/details",
    "/dmarc/domains/example.com/sources/192.0.2.250/details",
    "/dmarc/domains/example.com/tls-reports/2001-01-01/details",
])
def test_nothing_there_is_404(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", [
    "/dmarc/domains/example.com/reports/2026-13-40/details",
    "/dmarc/domains/example.com/tls-reports/2026-13-40/details",
    "/dmarc/domains/example.com/tls-reports/not-a-date/details",
])
def test_malformed_date_is_400(client, path):
    response = client.get(path)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid date format. Use YYYY-MM-DD"
