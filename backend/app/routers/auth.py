"""
OAuth2/OIDC Authentication Router
Handles OAuth2 login flow, callbacks, logout, and status
"""
import base64
import binascii
import hashlib
import hmac
import logging
import secrets
import re
import time
from collections import OrderedDict
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
from typing import Optional

from .. import auth as auth_module
from ..auth import safe_return_path, session_ended_response
from ..config import settings
from ..session import (
    create_session,
    SessionCapacityError,
    SessionRevokedError,
    get_session_from_request,
    record_activity,
    session_limits,
    delete_session,
    set_session_cookie,
    clear_session_cookie,
    SESSION_COOKIE_NAME,
    SESSION_ACCESS_CHANGED,
    is_secure_request,
    get_session_secret_key,
)
from ..services.oauth2_client import oauth2_client, OAuth2ClientError
from ..services import users_store
from .. import user_access
from ..agent_access.scopes import all_scopes
from ..api_models import documented
from ..api_models import auth as m

logger = logging.getLogger(__name__)

router = APIRouter()


def _admitted_generation(request: Request) -> int:
    """auth_generation() when the middleware admitted this request (auth.py).

    A request the middleware did not see gets no session at all, rather than
    one that skips the check.
    """
    generation = getattr(request.state, "auth_generation", None)
    if not isinstance(generation, int):
        raise SessionRevokedError("The request was not admitted by the sign-in middleware")
    return generation


# A login must be completed within ten minutes.
OAUTH_STATE_TTL = 600
OAUTH_COOKIE_PREFIX = "oauth_state_"
# Starting a login keeps nothing on the server, so unauthenticated clients
# cannot fill a shared store and block everyone's login. The state is
# "<expiry>.<HMAC>", signed over a random nonce that only the starting
# browser holds (in an HttpOnly cookie), the expiry and the return page.
# Callbacks are single-use: a consumed state is remembered until it expires.
# The application runs one worker, so this in-process record is complete.
# At the size limit the oldest entry is dropped; replaying it would still need
# the browser's cookie, and the provider accepts each authorization code once.
MAX_CONSUMED_OAUTH_STATES = 65536
_consumed_states: "OrderedDict[str, int]" = OrderedDict()
_STATE_RE = re.compile(r"(\d{1,12})\.([A-Za-z0-9_-]{43})")
_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _state_signature(nonce: str, expires: str, return_to: str) -> str:
    message = "\n".join(("oauth-state", nonce, expires, return_to)).encode("utf-8")
    return _b64(hmac.new(get_session_secret_key().encode("utf-8"), message, hashlib.sha256).digest())


def _pkce_verifier(nonce: str) -> str:
    """The PKCE code_verifier (RFC 7636) for the login started with this cookie nonce.

    Derived from the session secret, so the callback can recompute it without
    server-side storage, and it never appears in the state, the cookie or the
    authorization URL. 43 base64url characters, the minimum RFC 7636 allows.
    """
    message = "\n".join(("oauth-pkce", nonce)).encode("utf-8")
    return _b64(hmac.new(get_session_secret_key().encode("utf-8"), message, hashlib.sha256).digest())


def _pkce_challenge(verifier: str) -> str:
    """The S256 code_challenge for a code_verifier."""
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


def _new_browser_value(return_to: str) -> str:
    """The browser cookie value: a fresh random nonce plus the page to return to.

    It carries no secret; only the state sent to the provider is signed.
    """
    return f"{secrets.token_urlsafe(32)}.{_b64(return_to.encode('utf-8'))}"


def _signed_state(browser_value: str) -> str:
    """The state sent to the provider, signed over the cookie's nonce and return page."""
    nonce, _, encoded = browser_value.partition(".")
    return_to = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
    expires = str(int(time.time()) + OAUTH_STATE_TTL)
    return f"{expires}.{_state_signature(nonce, expires, return_to)}"


def _new_oauth_flow(return_to: str) -> tuple[str, str]:
    """A signed state for the provider and the matching value for the browser cookie."""
    browser_value = _new_browser_value(return_to)
    return _signed_state(browser_value), browser_value


def _verify_oauth_flow(state: Optional[str], cookie_value: str) -> Optional[str]:
    """The page to return to when state and cookie belong together and are current, else None."""
    match = _STATE_RE.fullmatch(state or "")
    nonce, _, encoded = (cookie_value or "").partition(".")
    if not match or not _NONCE_RE.fullmatch(nonce) or len(encoded) > 4096:
        return None
    try:
        return_to = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    expires, signature = match.groups()
    if int(expires) <= time.time():
        return None
    if not hmac.compare_digest(signature, _state_signature(nonce, expires, return_to)):
        return None
    return safe_return_path(return_to)


def _cleanup_oauth_states() -> None:
    """Forget used states that have expired (they can no longer pass verification)."""
    now = time.time()
    for state, expires in list(_consumed_states.items()):
        if expires <= now:
            del _consumed_states[state]


def _consume_oauth_state(state: str) -> bool:
    """Record a state as used; False when it was used before."""
    now = time.time()
    while _consumed_states:
        oldest, expires = next(iter(_consumed_states.items()))
        if expires > now and len(_consumed_states) < MAX_CONSUMED_OAUTH_STATES:
            break
        _consumed_states.pop(oldest)
    if state in _consumed_states:
        return False
    _consumed_states[state] = int(state.split(".", 1)[0])
    return True


def _oauth_redirect(url: str, state: str, request: Request) -> RedirectResponse:
    response = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    response.delete_cookie(
        key=OAUTH_COOKIE_PREFIX + state, path="/", httponly=True,
        secure=is_secure_request(request), samesite="lax",
    )
    return response


@router.get("/auth/verify", responses=documented(m.Verified))
def verify_basic_auth():
    """
    Verify Basic Auth credentials.
    Not in public_paths: middleware validates credentials and returns 401 if invalid.
    Used by the login form to test username/password before redirecting.
    """
    return {"verified": True}


_SIGN_IN_CHANGED = "Sign-in settings changed while you were signing in. Sign in again."


@router.post("/auth/session", responses=documented(m.BasicSession, errors={400: None, 401: None, 409: None, 429: None, 503: None}))
def create_basic_auth_session(request: Request):
    """
    Exchange verified Basic Auth credentials for a session cookie: the
    built-in admin's (AUTH_USERNAME), or a local user's (Settings > Users).

    The Authorization header is checked here on every call, through the same
    failure budget as everywhere else, also when the request carries a valid
    session cookie: a session never renews itself, only the password starts
    a new one with a new longest session. The password is never stored in
    the browser - the login form sends it once, here, and from then on the
    HttpOnly session cookie authenticates every request. Local users sign in
    only here, never with a Basic header on other calls.
    """
    if not settings.is_basic_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Basic authentication is not enabled",
        )
    client_ip = auth_module.sign_in_budget(request)
    credentials = auth_module.basic_credentials(request)
    wrong = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if credentials is None:
        raise wrong
    username, password = credentials
    if auth_module.verify_credentials(username, password):
        auth_module.clear_sign_in_failures(client_ip)
        return _new_session(request, {"username": username or settings.auth_username, "auth_method": "basic"},
                            {"kind": "builtin"})

    # Not the built-in admin: a local user, checked outside the failure counters' lock
    try:
        user = users_store.verify_sign_in(username, password)
    except users_store.SignInBusy:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=users_store.BUSY,
                            headers={"Retry-After": "1"})
    except Exception as e:
        # Not counted as a failure: an outage must not lock the client out
        logger.error(f"Could not check a local user's sign-in: {e}")
        raise _sign_in_unavailable()
    if user is None:
        auth_module.record_sign_in_failure(client_ip)
        raise wrong
    auth_module.clear_sign_in_failures(client_ip)
    try:
        version = users_store.current_auth_version(user["user_id"])
    except Exception as e:
        logger.error(f"Could not check a local user's sign-in: {e}")
        raise _sign_in_unavailable()
    if version != user["auth_version"]:
        # Changed by an admin while the password was checked
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_SIGN_IN_CHANGED)
    response = _new_session(request, {"username": user["username"], "auth_method": "basic"},
                            {"kind": "local", "user_id": user["user_id"], "auth_version": version})
    try:
        users_store.record_login(user["user_id"])
    except Exception as e:
        logger.warning(f"Could not record a local user's sign-in time: {e}")
    return response


def _sign_in_unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="Sign-in is not available right now. Try again in a moment.",
                         headers={"Retry-After": "5"})


def _new_session(request: Request, user_info: dict, principal: dict) -> JSONResponse:
    try:
        session_id = create_session(user_info, generation=_admitted_generation(request), principal=principal)
    except SessionRevokedError:
        # Sign-in changed after this login was let in, e.g. a new password:
        # a session now would outlive the change
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_SIGN_IN_CHANGED)
    except SessionCapacityError:
        raise HTTPException(
            status_code=503, detail="Login capacity reached. Try again later.",
            headers={"Retry-After": "60"},
        )
    response = JSONResponse(content={"authenticated": True, "auth_type": "basic"})
    set_session_cookie(response, session_id, request)
    logger.info("Basic Auth session created")
    return response


@router.get("/auth/provider-info", responses=documented(m.ProviderInfo))
def get_provider_info():
    """Get authentication provider information for frontend"""
    return {
        "oauth2_enabled": settings.is_oauth2_enabled,
        "basic_auth_enabled": settings.is_basic_auth_enabled,
        "provider_name": settings.oauth2_provider_name if settings.is_oauth2_enabled else None,
    }


@router.get("/auth/login", status_code=307, response_class=RedirectResponse, responses=documented(None, status=307, description="To the OAuth2 provider's sign-in page, with a short-lived cookie for this login", errors={400: None, 500: None}))
async def oauth2_login(request: Request, next: Optional[str] = None):
    """
    Initiate OAuth2 login flow
    Redirects user to OAuth2 provider; `next` is the local page to return to
    """
    if not settings.is_oauth2_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth2 authentication is not enabled"
        )
    
    if not oauth2_client.is_configured():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth2 client is not properly configured"
        )
    
    try:
        # Initialize client (perform discovery if needed)
        await oauth2_client.initialize()

        browser_value = _new_browser_value(safe_return_path(next))
        state = _signed_state(browser_value)
        nonce = browser_value.partition(".")[0]
        auth_url = oauth2_client.get_authorization_url(
            state, code_challenge=_pkce_challenge(_pkce_verifier(nonce)),
        )
        response = RedirectResponse(url=auth_url)
        # A separate cookie per flow permits concurrent logins in different tabs.
        # Lax allows the provider's top-level GET callback; no Domain scopes it
        # to this host. Follow the existing session cookie's HTTPS policy.
        response.set_cookie(
            key=OAUTH_COOKIE_PREFIX + state, value=browser_value,
            max_age=OAUTH_STATE_TTL, httponly=True,
            secure=is_secure_request(request), samesite="lax", path="/",
        )
        logger.info(f"Redirecting to OAuth2 provider: {settings.oauth2_provider_name}")
        return response
        
    except HTTPException:
        raise
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth2 is not configured correctly - see the application logs"
        )
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during OAuth2 login"
        )


@router.get("/auth/callback", status_code=302, response_class=RedirectResponse, responses=documented(None, status=302, description="Signed in: to the page the login started from, with the session cookie. Otherwise to /login?error=..., such as invalid_state, oauth2_error, session_capacity or no_access (an OAuth2 entry that is disabled, or a default of no access)", errors={400: None}))
async def oauth2_callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None
):
    """
    Handle OAuth2 callback from provider
    """
    if not settings.is_oauth2_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth2 authentication is not enabled"
        )
    
    browser_value = request.cookies.get(OAUTH_COOKIE_PREFIX + state, "") if state else ""
    return_to = _verify_oauth_flow(state, browser_value)
    # Consume before any await, including on provider errors or missing codes.
    # A callback from another browser must not consume the owner's state.
    if return_to is None or not _consume_oauth_state(state):
        logger.warning("Invalid, expired, reused or unbound state in OAuth2 callback")
        return RedirectResponse(url="/login?error=invalid_state", status_code=302)

    if error:
        logger.warning("OAuth2 provider declined authorization")
        return _oauth_redirect("/login?error=oauth2_error", state, request)

    if not code:
        logger.warning("Missing authorization code in OAuth2 callback")
        return _oauth_redirect("/login?error=missing_code", state, request)
    
    try:
        # Exchange code for token
        # The cookie's nonce was verified with the state above
        code_verifier = _pkce_verifier(browser_value.partition(".")[0])
        token_data = await oauth2_client.exchange_code_for_token(code, code_verifier=code_verifier)
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("No access token in token response")
            return _oauth_redirect("/login?error=no_token", state, request)
        
        # Get user information
        user_info = await oauth2_client.get_user_info(access_token)

        # The person's access, before any session exists: an entry that is
        # disabled, or a default of no access, signs nobody in
        principal = user_access.oauth2_ref(user_info)
        try:
            await run_in_threadpool(user_access.still_resolves, principal)
        except user_access.AccessEnded:
            logger.warning("OAuth2 login refused: this person has no access to the app")
            return _oauth_redirect("/login?error=no_access", state, request)

        # Create session, unless sign-in changed since the callback was let in
        session_id = create_session(user_info, generation=_admitted_generation(request), principal=principal)
        
        # Create response with redirect
        response = _oauth_redirect(return_to, state, request)
        
        # Set session cookie
        set_session_cookie(response, session_id, request)
        
        logger.info(f"OAuth2 login successful for user: {user_info.get('email', 'unknown')}")
        return response
        
    except SessionCapacityError:
        return _oauth_redirect("/login?error=session_capacity", state, request)
    except SessionRevokedError:
        logger.warning("Sign-in settings changed during an OAuth2 login; no session was issued")
        return _oauth_redirect("/login?error=sign_in_changed", state, request)
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 callback error: {e}")
        return _oauth_redirect("/login?error=oauth2_error", state, request)
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 callback: {e}", exc_info=True)
        return _oauth_redirect("/login?error=server_error", state, request)


@router.post("/auth/logout", status_code=302, response_class=RedirectResponse, responses=documented(None, status=302, description="Signed out: to /login, with the session cookie cleared"))
def oauth2_logout(request: Request):
    """
    Logout and clear session.
    POST only: a GET that ends the session lets any other site log the
    operator out with a link or an image. The same-origin guard rejects
    cross-site POSTs. GET answers 405.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    
    if session_id:
        delete_session(session_id)
    
    response = RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )
    
    clear_session_cookie(response, request)
    
    logger.info("User logged out")
    return response


@router.get("/auth/logout", include_in_schema=False)
def oauth2_logout_get():
    """Explicit 405: without this route the SPA catch-all would answer GET with the page."""
    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail="Log out with POST",
        headers={"Allow": "POST"},
    )


@router.post("/auth/activity", responses=documented(m.SessionActivity, errors={401: None, 503: None}))
def session_activity(request: Request):
    """
    The person used the page (typed, clicked, scrolled or touched): restart
    the inactivity time of this request's own session cookie.

    Pages that refresh by themselves never call this, so they do not keep a
    session alive. Only the cookie's own session is touched, and a session
    that ended stays ended. Not for agents.
    """
    if settings.is_authentication_enabled:
        access = user_access.cookie_access(request)
        if access == "ended":
            return session_ended_response(SESSION_ACCESS_CHANGED)
        if access == "unknown":
            raise HTTPException(status_code=503, detail=user_access.NOT_AVAILABLE, headers={"Retry-After": "5"})
    limits, ended = record_activity(request)
    if limits is None:
        if ended:
            return session_ended_response(ended)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session to keep active")
    return {"session": limits}


@router.get("/auth/status", responses=documented(m.AuthStatus))
def auth_status(request: Request):
    """
    Check authentication status
    Returns current user info if authenticated, and for a session cookie how
    long the session has left. Reading it never counts as activity.
    """
    # Who is asking and what they may do (user_access.py); everything while sign-in is off
    principal = getattr(request.state, "principal", None)
    who = {
        "user_name": principal.name if principal is not None and settings.is_authentication_enabled else None,
        "is_admin": bool(principal is not None and principal.is_admin),
        "scopes": [s for s in all_scopes() if principal is not None
                   and (principal.is_admin or s in principal.scopes)],
    }
    # Session cookie (OAuth2 login, or Basic Auth exchanged for a session)
    session_data = get_session_from_request(request)
    limits = session_limits(request) if session_data else None
    if session_data and limits is not None:
        user_info = session_data.get("user_info", {})
        return {
            "authenticated": True,
            "auth_type": user_info.get("auth_method", "oauth2"),
            "user": user_info,
            "session": limits,
            **who,
        }

    # Check Basic Auth (if enabled)
    if settings.is_basic_auth_enabled:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Basic "):
            # Basic Auth is present, but we don't return user info for Basic Auth
            # The middleware handles validation
            return {
                "authenticated": True,
                "auth_type": "basic",
                "user": None,  # Basic Auth doesn't provide user info
                "session": None,
                **who,
            }

    return {
        "authenticated": False,
        "auth_type": None,
        "user": None,
        "session": None,
        **who,
    }
