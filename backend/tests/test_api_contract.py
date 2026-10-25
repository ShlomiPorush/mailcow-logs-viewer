"""contract.py catches an answer that drifted from its documentation.

A small app of its own, so each kind of drift is shown on its own: a key the
model does not have, a wrong type, a missing key, a status the route does not
document. Operations that document nothing yet, and the statuses the auth
middleware gives any call, are not checked.
"""
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api_models import Fixed, Invalid, documented
from contract import Contract


class Thing(Fixed):
    name: str
    size: Optional[int]


def _app(answer, status=200):
    app = FastAPI()

    @app.get("/api/thing", responses=documented(Thing, errors={404: None, 422: Invalid}))
    def thing(fail: Optional[int] = None):
        if fail:
            raise HTTPException(status_code=fail, detail="no")
        return answer

    @app.get("/api/pending")
    def pending():
        return {"anything": 1}

    return app


def _problem(answer, path="/api/thing", status=None):
    app = _app(answer)
    response = TestClient(app, raise_server_exceptions=False).get(path)
    return Contract(app).problem("GET", path.split("?")[0], status or response.status_code,
                                 response.headers.get("content-type", ""), response.content)


def test_an_answer_that_matches_passes():
    assert _problem({"name": "a", "size": None}) is None


def test_an_undocumented_key_fails():
    assert "does not match" in _problem({"name": "a", "size": 1, "extra": True})


def test_a_wrong_type_fails():
    assert "does not match" in _problem({"name": "a", "size": "big"})


def test_a_missing_key_fails():
    assert "does not match" in _problem({"name": "a"})


def test_a_status_the_route_does_not_document_fails():
    assert "does not list" in _problem({}, "/api/thing?fail=409")


def test_documented_errors_pass():
    assert _problem({}, "/api/thing?fail=404") is None
    # FastAPI's own validation list and a detail string are both a documented 422
    assert _problem({}, "/api/thing?fail=x") is None
    assert _problem({}, "/api/thing?fail=422") is None


def test_the_statuses_the_middleware_gives_any_call_are_not_checked():
    assert _problem({}, "/api/thing?fail=401") is None


def test_an_operation_that_documents_nothing_yet_is_not_checked():
    assert _problem({}, "/api/pending") is None
