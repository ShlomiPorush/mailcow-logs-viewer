"""The OAuth 2.1 authorization server agents sign in through.

Public clients only. Two ways in: authorization code with PKCE (S256) for MCP
apps, where the browser runs on the agent's computer, and the device
authorization grant (RFC 8628) for agents that run the skill's script, where a
person approves with a short code on any device. Refresh tokens rotate.
Discovery follows RFC 9728 (protected resource) and RFC 8414 (authorization
server). Clients identify with a metadata document URL (CIMD, cimd.py) or
register themselves (RFC 7591, deprecated in MCP but still used). Every answer
to the client carries `iss` (RFC 9207) and returns `state` unchanged.

Every route here answers 404 while agent access is not live.
"""
import html
import json
import logging
import unicodedata
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
device_requests = Window(limit=10, seconds=3600)      # codes asked for, per address
code_lookups = Window(limit=10, seconds=600)          # codes typed or opened, per address and per session
unknown_device_codes = Window(limit=20, seconds=60)   # polls with a code that cannot succeed, per address

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
        "device_authorization_endpoint": base + "/oauth/device",
        "grant_types_supported": ["authorization_code", "refresh_token", DEVICE_GRANT],
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
    Every problem is shown here and never sent anywhere: anyone can register
    a redirect address, so the browser goes to it only with the person's
    answer on the consent page (RFC 9700 section 4.11.2).
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
            return error_page("This agent cannot connect", cimd.reason_text(e))
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
        return error_page("This agent cannot connect", "The agent asked for an answer type this app does not offer.")
    challenge = q.get("code_challenge") or ""
    if q.get("code_challenge_method") != "S256" or not (43 <= len(challenge) <= 128):
        return error_page("This agent cannot connect", "The agent did not send the PKCE S256 check this app requires.")
    resource = q.get("resource")
    if resource is not None and not live.same_resource(resource, live.resource()):
        return error_page("This agent cannot connect", "The agent asked for access to another server.")
    entry = pending.add(
        session_key=session_key, client_id=client_id, client_kind=kind, declared_name=declared,
        publisher=publisher, redirect_uri=redirect_uri, state=state, code_challenge=challenge,
        resource=live.resource(), requested=parse_scopes(q.get("scope")),
        sign_in=await db_call(store.sign_in_stamp),
    )
    return RedirectResponse(f"{CONSENT_PAGE}?request={entry.id}", status_code=302, headers=_NO_STORE)


# ── Agents that connect with a code (RFC 8628) ─────────────────────────────

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
_LABEL_PUNCTUATION = frozenset(" ._-()@:/")


def clean_label(raw: Optional[str]) -> Optional[str]:
    """The script's name for itself when it is plain text (letters, marks, digits, spaces and . _ - ( ) @ : /,
    1 to 60 characters); anything else, such as control or direction marks, quotes or markup, drops it."""
    if not isinstance(raw, str):
        return None
    label = unicodedata.normalize("NFC", raw).strip()
    if not 1 <= len(label) <= 60:
        return None
    if all(c in _LABEL_PUNCTUATION or unicodedata.category(c)[0] in "LMN" for c in label):
        return label
    return None


@router.post("/oauth/device")
async def device_authorization(request: Request):
    """An agent asks to connect: a secret device code for it, and a short code for the person to approve."""
    require_live()
    ip = _client_ip(request)
    if device_requests.full(ip):
        return _oauth_error("slow_down", "Too many connection requests from this address. Try again later.", 429)
    try:
        form = await _form(request)
    except HTTPException as e:
        return _oauth_error("invalid_request", str(e.detail), e.status_code if e.status_code == 413 else 400)
    if form.get("client_id") != store.DEVICE_CLIENT_ID:
        return _oauth_error("invalid_client", f"Use client_id={store.DEVICE_CLIENT_ID}.", 401)
    resource = form.get("resource")
    if resource is not None and not live.same_resource(resource, live.api_resource()):
        return _oauth_error("invalid_target", "The resource is not this server's API.")
    requested = " ".join(sorted(parse_scopes(form.get("scope"))))
    label = clean_label(form.get("client_label")) or "Script"
    if not device_requests.hit(ip):
        return _oauth_error("slow_down", "Too many connection requests from this address. Try again later.", 429)
    made = await db_call(store.create_device_request, client_id=store.DEVICE_CLIENT_ID, label=label,
                         requested=requested, resource=live.api_resource())
    if made is None:
        return _oauth_error("temporarily_unavailable", "Too many agents are waiting for approval. Try again in a few minutes.", 503)
    device_code, user_code = made
    shown = store.format_user_code(user_code)
    page = live.issuer() + "/oauth/device"
    return JSONResponse({
        "device_code": device_code,
        "user_code": shown,
        "verification_uri": page,
        "verification_uri_complete": f"{page}?user_code={shown}",
        "expires_in": store.DEVICE_SECONDS,
        "interval": store.DEVICE_INTERVAL,
    }, headers=_NO_STORE)


def code_page(message: Optional[str] = None, status_code: int = 200, value: str = "") -> HTMLResponse:
    """Where a person types the code their agent shows, when they did not open the agent's link."""
    note = f'<p class="ui-banner ui-banner-fail" role="alert">{html.escape(message)}</p>' if message else ""
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect an agent - mailcow Logs Viewer</title>
<link rel="stylesheet" href="/static/assets/css/ui.css">
<script>if(localStorage.getItem('theme')==='dark'||(!localStorage.getItem('theme')&&matchMedia('(prefers-color-scheme: dark)').matches))document.documentElement.classList.add('dark')</script>
</head><body class="ui-login"><main class="ui-login-card ui-consent-card">
<div class="ui-login-head"><img src="/static/assets/icons/app-icon.svg" alt="" class="ui-login-logo">
<h1 class="ui-h1">Connect an agent</h1></div>
{note}
<form method="get" action="/oauth/device" class="ui-consent-form">
<label class="ui-label" for="user-code">Enter the code your agent shows</label>
<input id="user-code" name="user_code" class="ui-input ui-consent-code-input" autocomplete="off" autocapitalize="characters"
 spellcheck="false" placeholder="XXXX-XXXX" maxlength="16" required value="{html.escape(value)}" autofocus>
<div class="ui-consent-actions"><button type="submit" class="ui-btn ui-btn-primary">Continue</button></div>
</form></main></body></html>"""
    return HTMLResponse(page, status_code=status_code, headers=_NO_STORE)


@router.get("/oauth/device")
async def device_page(request: Request):
    """The link the agent shows: checks the code, then opens the approval page for it.

    The middleware has already sent a signed-out browser to the login page.
    Every code tried counts against the person's address and session.
    """
    require_live()
    session_key = session_key_from_request(request)
    if not session_key:
        return error_page("Sign in first", "Open this page again after signing in.", 401)
    raw = request.query_params.get("user_code")
    if raw is None or not raw.strip():
        return code_page()
    ip = _client_ip(request)
    by_session = "session:" + session_key
    if code_lookups.full(ip) or code_lookups.full(by_session):
        return code_page("Too many codes tried. Wait 10 minutes, then try again.", 429)
    code_lookups.hit(ip)
    code_lookups.hit(by_session)
    found = await db_call(store.find_device_request, raw)
    if found is None:
        return code_page("This code is not valid or has expired. Check the code your agent shows, "
                         "or ask it to connect again.", 404, raw[:16])
    entry = pending.add(
        session_key=session_key, client_id=found["client_id"], client_kind="device",
        declared_name=found["label"], publisher=None, redirect_uri="", state=None, code_challenge="",
        resource=found["resource"], requested=parse_scopes(found["requested"]),
        sign_in=await db_call(store.sign_in_stamp),
        device_id=found["id"], user_code=store.format_user_code(found["user_code"]),
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
    ip = _client_ip(request)
    try:
        form = await _form(request)
    except HTTPException as e:
        return _oauth_error("invalid_request", str(e.detail), e.status_code if e.status_code == 413 else 400)
    grant_type = form.get("grant_type")
    # Polls of a known code are paced by the code itself (slow_down); several
    # agents behind one address must not use up the budget of the others
    if grant_type != DEVICE_GRANT and not token_requests.hit(ip):
        return _oauth_error("slow_down", "Too many requests. Try again in a minute.", 429)
    if grant_type == DEVICE_GRANT and unknown_device_codes.full(ip):
        return _oauth_error("slow_down", "Too many requests with an unknown code. Try again in a minute.", 429)
    client_id = form.get("client_id") or ""
    if not client_id:
        return _oauth_error("invalid_client", "client_id is required.", 401)
    try:
        if grant_type == DEVICE_GRANT:
            try:
                result = await db_call(store.redeem_device_code, device_code=form.get("device_code", ""),
                                       client_id=client_id)
            except store.TokenError as e:
                # Only a code still waiting is paced by the code itself; one that
                # can never succeed (unknown, used, denied, expired) counts here
                if e.error not in ("authorization_pending", "slow_down"):
                    unknown_device_codes.hit(ip)
                raise
        elif grant_type == "authorization_code":
            result = await db_call(store.exchange_code, code=form.get("code", ""), client_id=client_id,
                                   redirect_uri=form.get("redirect_uri", ""), verifier=form.get("code_verifier", ""),
                                   resource=form.get("resource"))
        elif grant_type == "refresh_token":
            result = await db_call(store.refresh_tokens, refresh_token=form.get("refresh_token", ""),
                                   client_id=client_id, scope=form.get("scope"), resource=form.get("resource"))
        else:
            return _oauth_error("unsupported_grant_type", "Use authorization_code, refresh_token or the device code grant.")
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
    for window in (registrations, token_requests, device_requests, code_lookups, unknown_device_codes):
        window.cleanup()
    pending.cleanup()
