import ast
import copy
import inspect
import json
import re
import textwrap
from typing import Any, Dict, Optional, Tuple

from conftest import registered_routes
from contract_rules import check_answer

MIDDLEWARE_OPERATIONS = {("GET", "/api/agent/access"), ("GET", "/api/agent/endpoints")}


class Contract:
    def __init__(self, app):
        self.app = app
        self._document = None
        self._routes = None

    @property
    def document(self) -> Dict[str, Any]:
        if self._document is None:
            self._document = copy.deepcopy(self.app.openapi())
        return self._document

    def operation_for(self, method: str, path: str) -> Optional[Tuple[str, Dict[str, Any]]]:
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
        if not path.startswith("/api/"):
            return None
        found = self.operation_for(method, path)
        if not found:
            return None
        template, operation = found
        outcome, detail = check_answer(operation, self.document.get("components", {}),
                                       status, content_type, body)
        return f"{method} {template}: {detail}" if outcome == "mismatch" else None


def agent_envelope(contract: "Contract", request, response) -> bool:
    if not request.headers.get("authorization", "").lower().startswith("bearer ") or response.status_code < 400:
        return False
    try:
        body = response.json()
    except ValueError:
        return False
    return (isinstance(body, dict) and set(body) == {"error", "message"}
            and all(isinstance(value, str) for value in body.values()))


def check_response(contract: Contract, response) -> None:
    request = response.request
    problem = contract.problem(request.method.upper(), request.url.path, response.status_code,
                               response.headers.get("content-type", ""), response.content)
    if problem and not agent_envelope(contract, request, response):
        raise AssertionError("The API answer does not match /openapi.json (app/api_models): " + problem)


def _literal_statuses(node) -> set:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _literal_statuses(node.body) | _literal_statuses(node.orelse)
    return set()


def statuses_in_source(function) -> set:
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
    names = schema_names(document)
    refs = re.findall(r'"\$ref": "#/components/schemas/([^"]+)"', json.dumps(document))
    return sorted({r for r in refs if r not in names})
