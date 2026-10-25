"""Every answer the app gives in a test must match what /openapi.json says it returns.

conftest.py wraps TestClient so each response of the real app (app.main.app)
to an /api call is checked here. The document's models (app/api_models) are
documentation only, so this is what keeps them true: a route that returns a
key, a type or a status its model does not have fails the test that called it.

An operation is checked once it documents a successful answer. Operations
still waiting for their models are listed in openapi_pending.py and skipped;
test_openapi_coverage.py keeps that list honest.
"""
import ast
import copy
import inspect
import json
import re
import textwrap
from typing import Any, Dict, Optional, Tuple

from jsonschema import Draft202012Validator

from conftest import registered_routes

# Answered by the auth middleware or the origin guard for any call, as the
# document's description says; a route documents them only when it gives them itself
APP_WIDE_STATUSES = {401, 403, 429}

# Answered by the auth middleware for an agent's bearer token, not by a route
MIDDLEWARE_OPERATIONS = {("GET", "/api/agent/access"), ("GET", "/api/agent/endpoints")}


def success_responses(operation: Dict[str, Any]) -> Dict[str, Any]:
    return {code: r for code, r in (operation.get("responses") or {}).items() if code[:1] in ("2", "3")}


def says_something(schema: Dict[str, Any]) -> bool:
    """Whether a schema describes an answer. FastAPI's default ({}) and the one it
    infers from a `-> Dict[str, Any]` annotation (any object) say nothing."""
    if not schema:
        return False
    if schema.get("type") == "object" and not schema.get("properties") \
            and schema.get("additionalProperties", True) in (True, {}):
        return False
    return True


def is_documented(operation: Optional[Dict[str, Any]]) -> bool:
    """Whether an operation says what it returns: a body schema, or a 3xx/204 without a body."""
    if not operation:
        return False
    for code, response in success_responses(operation).items():
        content = response.get("content")
        if not content:
            if code.startswith("3") or code == "204":
                return True
            continue
        if any(says_something(media.get("schema") or {}) for media in content.values()):
            return True
    return False


class Contract:
    def __init__(self, app):
        self.app = app
        self._document = None
        self._routes = None
        # (method, template, status) of every checked answer, for the CONTRACT_SEEN report (conftest.py)
        self.seen = set()

    @property
    def document(self) -> Dict[str, Any]:
        if self._document is None:
            self._document = copy.deepcopy(self.app.openapi())
        return self._document

    def operation_for(self, method: str, path: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """The route template a request reached and its operation in the document."""
        if (method, path) in MIDDLEWARE_OPERATIONS:
            template = path
        else:
            if self._routes is None:
                self._routes = [r for r in registered_routes(self.app)
                                if getattr(r, "path_regex", None) is not None and getattr(r, "methods", None)]
            template = next((r.path for r in self._routes
                             if method in r.methods and r.path_regex.match(path)), None)
            if template is None:
                return None
        operation = (self.document.get("paths", {}).get(template) or {}).get(method.lower())
        return (template, operation) if operation else None

    def problem(self, method: str, path: str, status: int, content_type: str, body: bytes) -> Optional[str]:
        """What is wrong with this answer, or None when it matches (or is not checked yet)."""
        if not path.startswith("/api/"):
            return None
        found = self.operation_for(method, path)
        if not found:
            return None
        template, operation = found
        if not is_documented(operation):
            return None
        where = f"{method} {template} answered {status}"
        self.seen.add((method, template, status))
        responses = operation.get("responses") or {}
        response = responses.get(str(status))
        if response is None:
            if status in APP_WIDE_STATUSES:
                return None
            return f"{where}, a status its documentation does not list: {body[:300]!r}"
        content = response.get("content") or {}
        if not content:
            return None if not body else f"{where} with a body, but its documentation says it has none"
        media = (content_type or "").split(";")[0].strip()
        if media not in content:
            return f"{where} as {media or 'no type'}, documented as {', '.join(content)}"
        schema = content[media].get("schema") or {}
        if media != "application/json" or not schema:
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return f"{where} with a body that is not JSON: {body[:300]!r}"
        validator = Draft202012Validator({**schema, "components": self.document.get("components", {})})
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
        if not errors:
            return None
        lines = [f"  at {'/'.join(str(p) for p in e.absolute_path) or '(top)'}: {e.message[:300]}" for e in errors[:5]]
        return f"{where} with an answer that does not match its documentation:\n" + "\n".join(lines)


def check_response(contract: Contract, response) -> None:
    """Fail the calling test when a response does not match the document."""
    request = response.request
    problem = contract.problem(request.method.upper(), request.url.path, response.status_code,
                               response.headers.get("content-type", ""), response.content)
    if problem:
        raise AssertionError("The API answer does not match /openapi.json (app/api_models): " + problem)


def _literal_statuses(node) -> set:
    """Status codes a status argument can take: a number, or either side of `a if c else b`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _literal_statuses(node.body) | _literal_statuses(node.orelse)
    return set()


def statuses_in_source(function) -> set:
    """The statuses a handler gives in its own code: HTTPException(...) and
    JSONResponse(...) with a literal status (keyword or, for HTTPException, the
    first argument; both sides of a conditional), and internal_error() (500).
    Comments and strings are not code, so they are not read. A status given in
    a helper the handler calls is not seen; the contract check still catches it
    when a test reaches it."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name == "internal_error":
            found.add(500)
        if name not in ("HTTPException", "JSONResponse"):
            continue
        for keyword in node.keywords:
            if keyword.arg == "status_code":
                found |= _literal_statuses(keyword.value)
        if name == "HTTPException" and node.args:
            found |= _literal_statuses(node.args[0])
    return found


def schema_names(document: Dict[str, Any]) -> set:
    return set((document.get("components") or {}).get("schemas", {}))


def unresolved_refs(document: Dict[str, Any]) -> list:
    """Every $ref in the document that names no component."""
    names = schema_names(document)
    refs = re.findall(r'"\$ref": "#/components/schemas/([^"]+)"', json.dumps(document))
    return sorted({r for r in refs if r not in names})
