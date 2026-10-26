"""Every API operation says what it returns in /openapi.json, or is listed as still to do.

The answers are described by app/api_models and checked against every test
call by contract.py. This file keeps the inventory honest: the operations come
from the routes the app registers (not from the document, which leaves out a
route that forgot to declare itself), plus the two agent calls the auth
middleware answers. HEAD and WebSocket routes are not API operations here.
"""
import json

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from jsonschema import Draft202012Validator  # noqa: E402

from app.main import app  # noqa: E402
from conftest import registered_routes  # noqa: E402
from contract import (MIDDLEWARE_OPERATIONS, Contract, is_documented, says_something, statuses_in_source,  # noqa: E402
                      unresolved_refs)
from openapi_pending import HIDDEN, PENDING  # noqa: E402


def _operations():
    """(method, path) -> whether the route is in the document, for every /api operation."""
    found = {}
    for route in registered_routes(app):
        methods = getattr(route, "methods", None)
        if not methods or not route.path.startswith("/api/"):
            continue
        for method in methods - {"HEAD"}:
            found[(method, route.path)] = getattr(route, "include_in_schema", True)
    for operation in MIDDLEWARE_OPERATIONS:
        found[operation] = True
    return found


def _document():
    return Contract(app).document


def test_every_operation_says_what_it_returns_or_is_pending():
    document = _document()
    missing = []
    for (method, path), in_schema in sorted(_operations().items()):
        if (method, path) in HIDDEN or (method, path) in PENDING:
            continue
        operation = (document["paths"].get(path) or {}).get(method.lower())
        if not in_schema or not is_documented(operation):
            missing.append(f"{method} {path}")
    assert missing == [], (
        "These operations do not say what they return. Describe the answer in app/api_models and pass it with "
        "responses=documented(...), or list the operation in tests/openapi_pending.py:\n  " + "\n  ".join(missing))


def test_the_pending_list_holds_only_operations_still_to_do():
    document, operations = _document(), _operations()
    stale = []
    for method, path in sorted(PENDING):
        if (method, path) not in operations:
            stale.append(f"{method} {path}: no such operation")
        elif is_documented((document["paths"].get(path) or {}).get(method.lower())):
            stale.append(f"{method} {path}: documented now, remove it from PENDING")
    for method, path in sorted(HIDDEN):
        if operations.get((method, path)) is not False:
            stale.append(f"{method} {path}: listed as hidden, but {'in the document' if (method, path) in operations else 'gone'}")
    assert stale == [], "tests/openapi_pending.py is out of date:\n  " + "\n  ".join(stale)


def test_every_documented_answer_has_a_real_schema():
    """No documented status may hide behind FastAPI's empty default."""
    empty = []
    for path, operations in _document()["paths"].items():
        for method, operation in operations.items():
            if not is_documented(operation):
                continue
            for code, response in (operation.get("responses") or {}).items():
                for media, body in (response.get("content") or {}).items():
                    if not says_something(body.get("schema") or {}):
                        empty.append(f"{method.upper()} {path} {code} {media}")
    assert empty == [], "Documented operations with an empty answer schema:\n  " + "\n  ".join(empty)


# Statuses the reader sees in a handler's code that the handler cannot give, and why
NOT_GIVEN = {
    ("GET", "/api/quarantine/{item_id}/details", 500): "the mailcow client turns every failure into "
                                                      "MailcowAPIError, which internal_error() answers 502",
    ("POST", "/api/dmarc/imap/sync", 500): "its try holds only a status update and queuing the import, "
                                          "which cannot fail",
    ("GET", "/api/status/version", 500): "every failure in its try is mailcow's (502) or caught in the GitHub "
                                         "check",
    ("GET", "/api/status/summary", 500): "gather(return_exceptions=True) turns every failure into a value",
    ("POST", "/api/fail2ban/unban", 500): "internal_error() is called only for a refused Read-Write key, "
                                          "which it answers 502",
}


def test_every_status_a_documented_handler_gives_is_documented():
    document = _document()
    missing, still_seen = [], set()
    for route in registered_routes(app):
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None or not route.path.startswith("/api/"):
            continue
        for method in (getattr(route, "methods", None) or set()) - {"HEAD"}:
            operation = (document["paths"].get(route.path) or {}).get(method.lower())
            if not is_documented(operation):
                continue
            for status in sorted(statuses_in_source(endpoint) - {int(c) for c in operation["responses"]}):
                if (method, route.path, status) in NOT_GIVEN:
                    still_seen.add((method, route.path, status))
                else:
                    missing.append(f"{method} {route.path} gives {status}")
    assert still_seen == set(NOT_GIVEN), "NOT_GIVEN lists statuses the reader no longer sees"
    assert missing == [], "Statuses these handlers give but do not document:\n  " + "\n  ".join(missing)


def test_the_document_is_whole():
    document = _document()
    assert unresolved_refs(document) == []
    for name, schema in document["components"]["schemas"].items():
        Draft202012Validator.check_schema(schema)
    json.dumps(document)


def test_agents_see_what_each_documented_call_returns():
    from types import SimpleNamespace

    from app.agent_access import scopes
    from app.agent_access.mcp import endpoints_info

    full_grant = SimpleNamespace(scopes=frozenset(scopes.all_scopes()))
    info = endpoints_info(app, full_grant, None)
    entries = {(e["method"], e["path"]): e for e in info["endpoints"]}
    assert entries[("GET", "/api/messages")]["returns"] == {
        "total": "integer", "page": "integer", "limit": "integer", "pages": "integer",
        "data": "array of MessageRow", "next_cursor": "string or null", "watermark": "integer"}
    undocumented = [k for k, e in entries.items() if k not in PENDING and "returns" not in e]
    assert undocumented == []
    # The whole list stays a size an agent can read in one go
    assert len(json.dumps(info)) < 200_000
