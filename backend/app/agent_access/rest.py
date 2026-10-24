"""REST for agents that connected with a code (the skill): /api with a bearer token.

The auth middleware hands every /api request that carries an Authorization
Bearer header here before any other check, so such a request is an agent's
whatever cookie it also carries, and a bad token never falls back to a session.
The call runs through the same path as an MCP call (dispatch.call_api): the
route the router picks is checked against the policy before it runs, with the
same body and answer limits, slots and timeout. Every call and refusal is
written to the agent's activity.

Errors are JSON {"error": <code>, "message": <text>}; the codes are the
skill's contract (skill_files/SKILL.md).
"""
import logging
from typing import Optional

from fastapi import HTTPException
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from . import dispatch, live, store
from . import scopes as policy
from .limits import read_body
from .mcp import access_info, endpoints_info, failed_tokens
from .oauth import db_call

logger = logging.getLogger(__name__)

ACCESS_PATH = "/api/agent/access"
ENDPOINTS_PATH = "/api/agent/endpoints"
MAX_ANSWER_CHARS = dispatch.MAX_RESPONSE_BYTES

_NO_STORE = {"Cache-Control": "no-store"}


def _error(status: int, code: str, message: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status, headers={**_NO_STORE, **(headers or {})})


def _unauthorized(message: str) -> JSONResponse:
    challenge = f'Bearer realm="mailcow Logs Viewer", error="invalid_token", error_description="{message}"'
    return _error(401, "invalid_token", message, {"WWW-Authenticate": challenge})


def _path_problem(path: str) -> Optional[str]:
    if not path.startswith("/api/") or len(path) > 1000:
        return "The path must start with /api/."
    if any(ord(c) < 32 or ord(c) == 127 for c in path) or "\\" in path:
        return "The path has characters the API does not use."
    if "//" in path or any(part in (".", "..") for part in path.split("/")):
        return "The path must not contain '..' or empty segments."
    return None


def _client_ip(request: Request) -> str:
    from ..auth import _client_ip as client_ip   # auth imports this module lazily
    return client_ip(request)


async def handle(request: Request) -> Response:
    if not live.is_live():
        return _unauthorized("Agent access is not available on this server. "
                             "The person who runs it can turn it on in Settings > Agents.")
    ip = _client_ip(request)
    if failed_tokens.full(ip):
        return _error(429, "too_many_requests", "Too many requests with a bad token. Wait 15 minutes.",
                      {"Retry-After": "900"})
    values = request.headers.getlist("authorization")
    if len(values) != 1 or values[0][:7].lower() != "bearer ":
        failed_tokens.hit(ip)
        return _unauthorized("Send exactly one Authorization: Bearer header.")
    grant = await db_call(store.validate_access_token, values[0][7:].strip(), live.api_resource())
    if grant is None:
        failed_tokens.hit(ip)
        return _unauthorized("The token is not valid or has ended. Refresh it, or connect again.")

    path = request.url.path
    method = request.method.upper()
    if path in (ACCESS_PATH, ENDPOINTS_PATH):
        if method != "GET":
            return _error(405, "not_found", "Use GET.", {"Allow": "GET"})
        if path == ACCESS_PATH:
            return JSONResponse(access_info(grant), headers=_NO_STORE)
        area = request.query_params.get("area") or None
        if area is not None and area not in policy.AREA_IDS:
            return _error(400, "bad_request", f"Unknown area. Use one of: {', '.join(sorted(policy.AREA_IDS))}.")
        return JSONResponse(await run_in_threadpool(endpoints_info, request.app, grant, area), headers=_NO_STORE)

    problem = _path_problem(path)
    if problem:
        return _error(400, "bad_request", problem)
    try:
        body = await read_body(request, dispatch.MAX_BODY_BYTES)
    except HTTPException:
        return _error(413, "too_large", "The body is too large (256 KB at most).")
    try:
        result = await dispatch.call_api(
            request.app, grant, None, method, path, None, None, request.scope.get("client"),
            raw_body=body, content_type=request.headers.get("content-type"),
            query_string=request.scope.get("query_string", b""), raw_path=request.scope.get("raw_path"),
            max_chars=MAX_ANSWER_CHARS,
        )
    except dispatch.Busy:
        return _error(429, "busy", "The app is still running this agent's earlier calls. Nothing was started; "
                                   "try again in a moment.")

    event = "denied" if result.outcome == "denied" else "call"
    detail = result.denied or (result.text[:200] if result.outcome == "error" else None)
    await db_call(lambda db: store.audit(db, event, grant, tool="rest", method=method, path=path,
                                         http_status=result.status, outcome=result.outcome, detail=detail))
    if result.outcome == "denied":
        return _error(403, "forbidden", result.denied or "Not available to agents.")
    if result.status == 413 and result.outcome == "error" and not result.path_template:
        return _error(413, "too_large", result.text)
    if result.truncated:
        return _error(502, "answer_too_large", "The answer is larger than 1 MB, so it was not sent. If this was "
                                               "an action it ran; read its state. Ask for less with the call's "
                                               "filters or limits.")
    if result.outcome == "accepted" and result.status == 504:
        return _error(504, "outcome_unknown", result.text)
    if result.path_template is None and result.status in (404, 405):
        return _error(result.status, "not_found", "No such API call for this method. Take the path from "
                                                  "`mailcow-logs endpoints`; do not guess it.")
    if result.path_template and policy.POLICY.get((method, result.path_template), None) is not None \
            and policy.POLICY[(method, result.path_template)].kind == policy.WRITE:
        logger.info(f"Agent '{grant.name}' ran {method} {path}: HTTP {result.status} ({result.outcome})")
    return Response(content=result.text, status_code=result.status,
                    media_type=result.content_type or "application/octet-stream", headers=_NO_STORE)
