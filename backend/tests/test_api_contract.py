"""contract.py catches an answer that drifted from its documentation.

A small app of its own, so each kind of drift is shown on its own: a key the
model does not have, a wrong type, a missing key, a status the route does not
document. Operations that document nothing yet, and the statuses the auth
middleware gives any call, are not checked.
"""
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.api_models import Fixed, Invalid, documented
from app.utils import internal_error
from contract import Contract, agent_envelope, statuses_in_source


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


def _handler(ok, missing, cursor):
    # "status_code=418" in a comment or a string is not code
    if not ok:
        raise HTTPException(404, "gone")
    if missing:
        raise HTTPException(status_code=409, detail="status_code=418")
    if cursor:
        return JSONResponse(content=dict(a=1), status_code=200 if ok else 503)
    try:
        return {}
    except Exception as e:
        raise internal_error(e)


def test_the_status_reader_sees_every_way_a_handler_writes_one():
    assert statuses_in_source(_handler) == {404, 409, 200, 503, 500}


def test_the_sign_in_set_up_without_a_password_is_not_a_route_answer(monkeypatch):
    # The auth middleware answers any call that needs sign-in with a plain 500 then
    import starlette.staticfiles as sf
    orig = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, "__init__", lambda s, *a, **k: orig(s, *a, **{**k, "check_dir": False}))
    from app.config import settings
    from app.main import app
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_password", "")
    response = TestClient(app).get("/api/messages", headers={"Authorization": "Basic eDp5"})
    assert response.status_code == 500 and "password is not configured" in response.text
    assert Contract(app).problem("GET", "/api/messages", 500, response.headers.get("content-type", ""),
                                 response.content) is None


def _bearer_answer(status, body):
    import httpx
    request = httpx.Request("GET", "http://testserver/api/thing", headers={"Authorization": "Bearer t"})
    return request, httpx.Response(status, json=body, request=request)


def test_a_bearer_call_may_get_the_route_answer_or_the_gateway_envelope():
    import pytest
    from contract import check_response
    contract = Contract(_app({}))
    envelope = {"error": "forbidden", "message": "Not available to agents."}
    # The gateway's own answer, at a status the route does not document or does
    assert agent_envelope(contract, *_bearer_answer(413, envelope))
    check_response(contract, _bearer_answer(404, envelope)[1])
    # The route's documented answer passes as always
    check_response(contract, _bearer_answer(404, {"detail": "gone"})[1])
    # Neither the route's answer nor the envelope fails
    with pytest.raises(AssertionError):
        check_response(contract, _bearer_answer(404, {"detail": 5})[1])
    assert not agent_envelope(contract, *_bearer_answer(413, {"error": 1, "message": "x"}))


def test_only_a_checked_answer_that_matches_counts_as_reached():
    from contract import check_response
    contract = Contract(_app({}))
    # The gateway's envelope and the sign-in middleware's plain 500 are not the route's answers
    check_response(contract, _bearer_answer(404, {"error": "gone", "message": "Not found."})[1])
    assert contract.problem("GET", "/api/thing", 500, "text/plain",
                            b"Authentication is enabled but password is not configured") is None
    assert contract.seen == set()
    check_response(contract, _bearer_answer(404, {"detail": "gone"})[1])
    assert contract.seen == {("GET", "/api/thing", 404)}
