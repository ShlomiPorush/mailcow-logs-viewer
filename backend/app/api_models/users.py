"""What Settings > Users calls return (routers/users.py). For admins only."""
from typing import Dict, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class UserAreaInfo(Fixed):
    """An area a person can be given View, and Act, on. Settings is not one: it is for admins."""
    id: str
    label: str
    view: str = Field(description="What View allows")
    act: str = Field(description="What Act allows; empty when the area has no actions")


class AccessPreset(Fixed):
    """An access level and the areas it gives today (a preset covers a new area by itself)."""
    id: str = Field(description="admin, operator, viewer or custom")
    label: str
    areas: Dict[str, str] = Field(description="area id -> view or act; empty for custom, which has its own")


class BuiltinAdmin(Fixed):
    """The admin set by AUTH_USERNAME and AUTH_PASSWORD, which is not a stored user."""
    username: str
    basic_auth_enabled: bool


class OAuth2Access(Fixed):
    """What everyone the OAuth2 provider signs in gets, unless an entry gives their email its own access."""
    enabled: bool = Field(description="Whether OAuth2 sign-in is on")
    default_access: str = Field(description="admin, operator, viewer or none (no access)")
    version: int = Field(description="Send it with a change, so a change made meanwhile is not undone")
    provider_name: str = Field(description="The provider's name as set (OAUTH2_PROVIDER_NAME); empty when not set")


class You(Fixed):
    """Who asked: the built-in admin, a local user, or a person OAuth2 signed in."""
    kind: str = Field(description="builtin, local or oauth2")
    user_id: Optional[int] = Field(description="The local user's id, or the OAuth2 entry's for this email; null otherwise")
    via_default: bool = Field(description="An OAuth2 person without an entry, who gets the access for everyone else")


class UserRow(Fixed):
    """A local user (username and password) or an OAuth2 entry (an email address)."""
    id: int
    kind: str = Field(description="local or oauth2")
    username: Optional[str] = Field(description="A local user's username; null for an OAuth2 entry")
    email: Optional[str] = Field(description="An OAuth2 entry's email address; null for a local user")
    access: str = Field(description="admin, operator, viewer or custom")
    areas: Dict[str, str] = Field(description="area id -> view or act, as the access gives today")
    disabled: bool
    name_conflict: bool = Field(description="A local user with the built-in admin's username: the built-in admin "
                                            "wins and this user cannot sign in")
    last_login_at: Optional[str] = Field(description="A local user's last sign-in, " + TIME + "; null before the first")
    created_at: str = Field(description=TIME)
    row_version: int = Field(description="Send it with a change, so a change made meanwhile is not undone")


class UsersOverview(Fixed):
    """Settings > Users: who can sign in and what they may do."""
    areas: List[UserAreaInfo]
    presets: List[AccessPreset]
    builtin: BuiltinAdmin
    oauth2: OAuth2Access
    you: You
    users: List[UserRow]


class UserDeleted(Fixed):
    deleted: int = Field(description="1")


class OAuth2DefaultSaved(Fixed):
    """The OAuth2 default access was saved."""
    default_access: str = Field(description="admin, operator, viewer or none")
    version: int = Field(description="The new version, for the next change")
