"""What the sign-in calls return (routers/auth.py)."""
from typing import Any, Dict, Optional

from pydantic import Field

from . import Fixed


class Verified(Fixed):
    """The Basic Auth credentials were accepted (the sign-in check refuses wrong ones with 401)."""
    verified: bool = Field(description="true")


class BasicSession(Fixed):
    """The session cookie is set (HttpOnly); it signs in every later call."""
    authenticated: bool = Field(description="true")
    auth_type: str = Field(description="basic")


class ProviderInfo(Fixed):
    """Which sign-in methods the login page offers."""
    oauth2_enabled: bool
    basic_auth_enabled: bool
    provider_name: Optional[str] = Field(description="The OAuth2 provider's name; null when OAuth2 is off")


class AuthStatus(Fixed):
    """Whether this call is signed in, and as whom."""
    authenticated: bool
    auth_type: Optional[str] = Field(description="oauth2 or basic; null when not signed in")
    user: Optional[Dict[str, Any]] = Field(description="The session's user: the OAuth2 provider's user info as it "
                                                       "sent it, or username and auth_method after a Basic sign-in. "
                                                       "Null for Basic Auth without a session and when not signed in")
