"""The OAuth 2.1 authorization server agents sign in through.

Public clients only, PKCE (S256) required, authorization code + refresh token.
Discovery follows RFC 9728 (protected resource) and RFC 8414 (authorization
server). Clients identify with a metadata document URL (CIMD, cimd.py) or
register themselves (RFC 7591, deprecated in MCP but still used). Every answer
to the client carries `iss` (RFC 9207) and returns `state` unchanged.

Every route here answers 404 while agent access is not live.
"""
import html
import json
import logging
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from ..auth import _client_ip
from ..database import SessionLocal
from ..session import session_key_from_request
from . import cimd, live, pending, store
from .limits import Window, read_body
from .scopes import all_scopes, parse_scopes, read_scopes

logger = logging.getLogger(__name__)

router = APIRouter(include_in_schema=False)

CONSENT_PAGE = "/oauth/consent"
MAX_FORM_BYTES = 16 * 1024
MAX_REDIRECT_URIS = 10
MAX_URI_LENGTH = 512
_FORBIDDEN_SCHEMES = frozenset({"javascript", "data", "file", "vbscript", "about", "blob", "http", "https"})

registrations = Window(limit=10, seconds=3600)
token_requests = Window(limit=30, seconds=60)

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

# Consents waiting in the browser end too when every agent is disconnected
store.on_disconnect_all.append(pending.clear)


def require_live() -> None:
    if not live.is_live():
        raise HTTPException(status_code=404, detail="Not Found")


def db_call(fn, *args, **kwargs):
    """Run fn(db, ...) on a fresh session in the thread pool."""
    def run():
        db = SessionLocal()
        try:
            return fn(db, *args, **kwargs)
        finally:
            db.close()
    return run_in_threadpool(run)


# ── Redirect addresses ─────────────────────────────────────────────────────

def valid_redirect_uri(uri: str) -> bool:
    """https anywhere, http only on a loopback host, or a private-use scheme of a native app."""
    if not isinstance(uri, str) or not uri or len(uri) > MAX_URI_LENGTH:
        return False
    if any(ord(c) < 33 or ord(c) == 127 for c in uri):
        return False
    try:
        parts = urlsplit(uri)
        parts.port
    except ValueError:
        return False
    scheme = parts.scheme.lower()
    if parts.fragment or parts.username or parts.password:
        return False
    if scheme == "https":
        return bool(parts.hostname)
    if scheme == "http":
        return bool(parts.hostname) and live.is_loopback_host(parts.hostname)
    # A private-use scheme (RFC 8252 7.1) is a reverse domain name, such as com.example.app
    return "." in scheme and scheme not in _FORBIDDEN_SCHEMES and scheme.replace(".", "").replace("-", "").replace("+", "").isalnum()


def redirect_matches(registered: List[str], given: str) -> bool:
    """Exact match, except that a loopback http address may use any port (RFC 8252 7.3).

    Only the port may differ: the host as written, the path and the query must
    be the same.
    """
    if not given or not valid_redirect_uri(given):
        return False
    if given in registered:
        return True
    try:
        g = urlsplit(given)
        if g.scheme != "http" or not live.is_loopback_host(g.hostname or ""):
            return False
        for uri in registered:
            r = urlsplit(uri)
            if r.scheme == "http" and r.hostname == g.hostname and r.path == g.path and r.query == g.query:
                return True
    except ValueError:
        return False
    return False


def with_params(uri: str, params: Dict[str, Optional[str]]) -> str:
    """The redirect address with the answer added to its query (its own query kept)."""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def client_redirect(uri: str, state: Optional[str], **params) -> RedirectResponse:
    params["state"] = state
    params["iss"] = live.issuer()
    return RedirectResponse(with_params(uri, params), status_code=302, headers=_NO_STORE)


def error_page(title: str, message: str, status_code: int = 400) -> HTMLResponse:
    """Shown in the browser when the request cannot be answered to the client."""
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} - mailcow Logs Viewer</title>
<link rel="stylesheet" href="/static/assets/css/ui.css">
<script>if(localStorage.getItem('theme')==='dark'||(!localStorage.getItem('theme')&&matchMedia('(prefers-color-scheme: dark)').matches))document.documentElement.classList.add('dark')</script>
</head><body class="ui-login"><main class="ui-panel ui-login-card ui-consent-card">
<h1 class="ui-h1">{html.escape(title)}</h1><p>{html.escape(message)}</p>
<p class="ui-muted">Close this window and connect the agent again. Nothing was shared with it.</p>
</main></body></html>"""
    return HTMLResponse(page, status_code=status_code, headers=_NO_STORE)


# ── Discovery ──────────────────────────────────────────────────────────────

def _protected_resource() -> Dict:
    return {
        "resource": live.resource(),
        "authorization_servers": [live.issuer()],
        "scopes_supported": list(read_scopes()),
        "bearer_methods_supported": ["header"],
        "resource_name": "mailcow Logs Viewer",
    }


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_metadata():
    require_live()
    return JSONResponse(_protected_resource())


@router.get("/.well-known/oauth-authorization-server")
def authorization_server_metadata():
    require_live()
    base = live.issuer()
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "registration_endpoint": base + "/oauth/register",
        "revocation_endpoint": base + "/oauth/revoke",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": list(all_scopes()),
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": True,
    })


# ── Authorization ──────────────────────────────────────────────────────────

@router.get("/oauth/authorize")
async def authorize(request: Request):
    """Check the request, then hand it to the consent page.

    The middleware has already sent a signed-out browser to the login page.
    Until the client and its redirect address are known good, problems are
    shown here and never sent anywhere.
    """
    require_live()
    q = request.query_params
    session_key = session_key_from_request(request)
    if not session_key:
        return error_page("Sign in first", "Open this page again after signing in.", 401)
    client_id = q.get("client_id") or ""
    redirect_uri = q.get("redirect_uri") or ""
    if cimd.is_document_client_id(client_id):
        try:
            document = await cimd.fetch(client_id)
        except cimd.ClientDocumentError as e:
            return error_page("This agent cannot connect", str(e))
        kind, declared, publisher, registered = "cimd", document.client_name, document.publisher, list(document.redirect_uris)
    else:
        client = await db_call(store.get_client, client_id)
        if client is None:
            return error_page("This agent cannot connect", "The app does not know this agent. Connect it again so it can register.")
        kind, declared, publisher, registered = "dcr", client.client_name, None, list(client.redirect_uris or [])
    if not redirect_matches(registered, redirect_uri):
        return error_page("This agent cannot connect", "The agent asked to send the answer to an address it did not register.")

    state = q.get("state")
    if q.get("response_type") != "code":
        return client_redirect(redirect_uri, state, error="unsupported_response_type",
                               error_description="Only response_type=code is supported.")
    challenge = q.get("code_challenge") or ""
    if q.get("code_challenge_method") != "S256" or not (43 <= len(challenge) <= 128):
        return client_redirect(redirect_uri, state, error="invalid_request",
                               error_description="PKCE with S256 is required.")
    resource = q.get("resource")
    if resource is not None and not live.same_resource(resource, live.resource()):
        return client_redirect(redirect_uri, state, error="invalid_target",
                               error_description="The resource is not this server.")
    entry = pending.add(
        session_key=session_key, client_id=client_id, client_kind=kind, declared_name=declared,
        publisher=publisher, redirect_uri=redirect_uri, state=state, code_challenge=challenge,
        resource=live.resource(), requested=parse_scopes(q.get("scope")),
    )
    return RedirectResponse(f"{CONSENT_PAGE}?request={entry.id}", status_code=302, headers=_NO_STORE)


# ── Token, registration and revocation ─────────────────────────────────────

def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status_code, headers=_NO_STORE)


async def _form(request: Request) -> Dict[str, str]:
    body = await read_body(request, MAX_FORM_BYTES)
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=400, detail="Send the request form-encoded.")
    try:
        pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="The request is not valid.")
    form: Dict[str, str] = {}
    for key, value in pairs:
        if key in form:
            raise HTTPException(status_code=400, detail=f"'{key}' appears more than once.")
        form[key] = value
    return form


@router.post("/oauth/token")
async def token(request: Request):
    require_live()
    if not token_requests.hit(_client_ip(request)):
        return _oauth_error("slow_down", "Too many requests. Try again in a minute.", 429)
    try:
        form = await _form(request)
    except HTTPException as e:
        return _oauth_error("invalid_request", str(e.detail), e.status_code if e.status_code == 413 else 400)
    grant_type = form.get("grant_type")
    client_id = form.get("client_id") or ""
    if not client_id:
        return _oauth_error("invalid_client", "client_id is required.", 401)
    try:
        if grant_type == "authorization_code":
            result = await db_call(store.exchange_code, code=form.get("code", ""), client_id=client_id,
                                   redirect_uri=form.get("redirect_uri", ""), verifier=form.get("code_verifier", ""),
                                   resource=form.get("resource"))
        elif grant_type == "refresh_token":
            result = await db_call(store.refresh_tokens, refresh_token=form.get("refresh_token", ""),
                                   client_id=client_id, scope=form.get("scope"), resource=form.get("resource"))
        else:
            return _oauth_error("unsupported_grant_type", "Use authorization_code or refresh_token.")
    except store.TokenError as e:
        return _oauth_error(e.error, e.description)
    return JSONResponse(result, headers=_NO_STORE)


@router.post("/oauth/register")
async def register(request: Request):
    """Dynamic Client Registration (RFC 7591) for public clients."""
    require_live()
    ip = _client_ip(request)
    if registrations.full(ip):
        return _oauth_error("too_many_requests", "Too many registrations from this address. Try again later.", 429)
    try:
        body = await read_body(request, MAX_FORM_BYTES)
        data = json.loads(body.decode("utf-8") or "null")
    except HTTPException as e:
        return _oauth_error("invalid_client_metadata", str(e.detail), e.status_code)
    except (UnicodeDecodeError, ValueError):
        return _oauth_error("invalid_client_metadata", "The request is not valid JSON.")
    if not isinstance(data, dict):
        return _oauth_error("invalid_client_metadata", "Send a JSON object.")
    uris = data.get("redirect_uris")
    if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
        return _oauth_error("invalid_redirect_uri", f"Send 1 to {MAX_REDIRECT_URIS} redirect_uris.")
    if not all(isinstance(u, str) and valid_redirect_uri(u) for u in uris):
        return _oauth_error("invalid_redirect_uri",
                            "Redirect addresses must be https, http on a loopback host, or a private-use scheme.")
    name = data.get("client_name")
    name = name.strip()[:100] if isinstance(name, str) and name.strip() else "Unnamed agent"
    grant_types = data.get("grant_types", ["authorization_code"])
    if not isinstance(grant_types, list) or "authorization_code" not in grant_types \
            or any(g not in ("authorization_code", "refresh_token") for g in grant_types):
        return _oauth_error("invalid_client_metadata", "Only authorization_code and refresh_token are supported.")
    if not registrations.hit(ip):
        return _oauth_error("too_many_requests", "Too many registrations from this address. Try again later.", 429)
    client = await db_call(store.register_client, name, list(dict.fromkeys(uris)), ip)
    if client is None:
        return _oauth_error("temporarily_unavailable", "Too many agents are registering. Try again in a few minutes.", 503)
    return JSONResponse({
        "client_id": client.client_id,
        "client_id_issued_at": int(client.created_at.timestamp()),
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }, status_code=201, headers=_NO_STORE)


@router.post("/oauth/revoke")
async def revoke(request: Request):
    """RFC 7009. Always 200 for a well-formed request, whether or not the token was known."""
    require_live()
    if not token_requests.hit(_client_ip(request)):
        return _oauth_error("slow_down", "Too many requests. Try again in a minute.", 429)
    try:
        form = await _form(request)
    except HTTPException as e:
        return _oauth_error("invalid_request", str(e.detail), e.status_code if e.status_code == 413 else 400)
    if not form.get("token") or not form.get("client_id"):
        return _oauth_error("invalid_request", "token and client_id are required.")
    await db_call(store.revoke_token, form["token"], form["client_id"])
    return Response(status_code=200, headers=_NO_STORE)


def cleanup() -> None:
    registrations.cleanup()
    token_requests.cleanup()
    pending.cleanup()
