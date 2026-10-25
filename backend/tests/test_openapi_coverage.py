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
from contract import (MIDDLEWARE_OPERATIONS, Contract, is_documented, says_something,  # noqa: E402
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
