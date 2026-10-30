"""Settings > Users: local users, OAuth2 entries and the OAuth2 default access.

Admins only (user_access.py), and never agents (agent_access/scopes.py). A
change to a user applies to that user's next request: a new password, new
access, or disabling ends their sessions. Kind, username and email cannot be
changed; delete the user and add them again.
"""
import logging
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ..api_models import Invalid, documented
from ..api_models import users as m
from ..database import get_db
from ..services import users_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

Access = Literal["admin", "operator", "viewer", "custom"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NewUser(_Body):
    kind: Literal["local", "oauth2"]
    username: Optional[str] = Field(default=None, max_length=200, description="A local user's username")
    email: Optional[str] = Field(default=None, max_length=320, description="An OAuth2 entry's email address")
    password: Optional[str] = Field(default=None, max_length=1024, description="A local user's password, 12 to 256 characters")
    access: Access
    views: List[str] = Field(default_factory=list, max_length=50, description="custom: the areas with View")
    acts: List[str] = Field(default_factory=list, max_length=50, description="custom: the areas with Act (includes View)")
    disabled: bool = False


class UserChange(_Body):
    access: Access
    views: List[str] = Field(default_factory=list, max_length=50)
    acts: List[str] = Field(default_factory=list, max_length=50)
    disabled: bool
    password: Optional[str] = Field(default=None, max_length=1024, description="A new password for a local user; "
                                                                               "leave out to keep it")
    row_version: int = Field(description="The row_version the change was made on")


class DefaultChange(_Body):
    value: Literal["admin", "operator", "viewer", "none"]
    version: int = Field(description="The version the change was made on")


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except users_store.UserError as e:
        raise HTTPException(status_code=e.status, detail=e.detail)


@router.get("", responses=documented(m.UsersOverview, errors={500: None}))
def list_users(db: Session = Depends(get_db)):
    """Who can sign in and with what access, with the areas and presets to choose from."""
    return users_store.overview(db)


@router.post("", status_code=201, responses=documented(m.UserRow, status=201, errors={409: None, 422: Invalid, 500: None}))
def create_user(body: NewUser, db: Session = Depends(get_db)):
    """Add a local user or an OAuth2 entry. 409 for a name or email already there, the built-in
    admin's username, or a change that would leave no admin who can sign in."""
    return _run(users_store.create_user, db, kind=body.kind, username=body.username, email=body.email,
                password=body.password, access_level=body.access, views=body.views, acts=body.acts,
                disabled=body.disabled)


@router.put("/oauth2-default", responses=documented(m.OAuth2DefaultSaved, errors={409: None, 422: Invalid, 500: None}))
def set_oauth2_default(body: DefaultChange, db: Session = Depends(get_db)):
    """What everyone the OAuth2 provider signs in gets without an entry of their own; none signs them out.
    Applies to sessions already open."""
    return _run(users_store.set_default, db, body.value, body.version)


@router.put("/{user_id}", responses=documented(m.UserRow, errors={404: None, 409: None, 422: Invalid, 500: None}))
def change_user(user_id: int, body: UserChange, db: Session = Depends(get_db)):
    """Change a user's access, password or whether they are disabled. 409 when the user changed
    since row_version, or when no admin could sign in afterwards."""
    return _run(users_store.update_user, db, user_id, access_level=body.access, views=body.views, acts=body.acts,
                disabled=body.disabled, password=body.password, row_version=body.row_version)


@router.delete("/{user_id}", responses=documented(m.UserDeleted, errors={404: None, 409: None, 422: Invalid, 500: None}))
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Delete a user; their sessions end. An OAuth2 entry's person gets the OAuth2 default again."""
    _run(users_store.delete_user, db, user_id)
    return {"deleted": 1}
