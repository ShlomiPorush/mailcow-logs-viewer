"""What /api/health and /api/info return (main.py)."""
from typing import List, Optional

from pydantic import Field

from . import Fixed


class HealthResponse(Fixed):
    """Whether the app can reach its database. Public, for Docker's health check."""
    status: str = Field(description="healthy, or unhealthy (HTTP 503)")
    database: str = Field(description="connected or disconnected")


class InfoResponse(Fixed):
    """The app's name, sign-in methods and, for a signed-in caller, its settings.

    Public, because the login page needs it. The fields after `oauth2_enabled`
    are only there when the request is signed in.
    """
    name: str
    app_title: str
    app_logo_url: Optional[str]
    auth_enabled: bool
    basic_auth_enabled: bool
    oauth2_enabled: bool
    version: str = Field(None, description="Signed in only")
    mailcow_url: str = Field(None, description="Signed in only")
    local_domains: List[str] = Field(None, description="Signed in only: the domains mailcow hosts")
    fetch_interval: int = Field(None, description="Signed in only: seconds between log fetches")
    retention_days: int = Field(None, description="Signed in only")
    timezone: str = Field(None, description="Signed in only: the zone every time on screen follows")
    timezone_valid: bool = Field(None, description="Signed in only: whether TZ names a known zone")
    timezone_configured: Optional[str] = Field(None, description="Signed in only: TZ as configured")
    date_format: str = Field(None, description="Signed in only")
    time_format: str = Field(None, description="Signed in only")
    blacklist_count: int = Field(None, description="Signed in only: addresses hidden by Addresses to exclude")
    disabled_features: List[str] = Field(None, description="Signed in only")
    settings_edit_via_ui_enabled: bool = Field(None, description="Signed in only: whether Settings can be edited")
