"""
What the API returns, for the OpenAPI document only.

The routes build their answers as plain dicts. These models describe them so
the API reference (/docs) and agents (list_endpoints) can show each answer.
They are passed to the route decorator through ``responses=`` (see
``documented``), which only adds them to /openapi.json: the answer is never
filtered or validated by them. Never pass them as ``response_model`` and never
annotate a route with ``-> SomeResponse``; FastAPI would then run every answer
through the model and could drop fields or turn a mismatch into a 500. A route
annotated `-> Dict[str, Any]` gets ``response_model=None`` beside ``responses=``,
or the model FastAPI infers from it would replace the description.

The tests check every answer the app gives against these models
(tests/contract.py), so a model that drifts from its route fails CI.

Conventions:
- A fixed shape forbids other keys (``Fixed``), so an undocumented key fails.
- A key that is sometimes missing has a default and is not required; a key
  that is always there but may be null is ``X | None`` without a default.
- Keys chosen at run time (a name, a date) are ``dict[str, Model]``.
- Data passed through as another system sent it is ``dict[str, Any]``, with
  a description saying so.
"""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response


class Fixed(BaseModel):
    """A response object with exactly these keys."""
    model_config = ConfigDict(extra="forbid")


class ErrorDetail(Fixed):
    """An error: what went wrong, in words."""
    detail: str = Field(description="What went wrong")


class SessionEnded(Fixed):
    """A session cookie that a limit ended; the X-Session-End header carries the reason too."""
    detail: str = Field(description="What happened")
    reason: str = Field(description="session_expired (the longest session), session_idle (inactivity) or "
                                    "access_changed (the person's account changed or no longer gives access)")


# Not signed in: the route's own sentence, or a session a limit ended (the
# sign-in check's plain-text answer is app-wide, in the document's description)
NotSignedIn = Union[SessionEnded, ErrorDetail]


class ServerError(Fixed):
    """An internal error. A failure the route did not catch also has `error` (main.py's handler)."""
    detail: str = Field(description="What went wrong; the details are in the container log")
    error: str = Field(None, description="Only for a failure the route did not catch")


class ValidationErrorItem(BaseModel):
    """One problem with the request, as FastAPI reports it."""
    model_config = ConfigDict(extra="allow")
    type: str
    loc: List[Union[str, int]] = Field(description="Where the problem is, such as ['query', 'limit']")
    msg: str


class ValidationErrors(Fixed):
    """The request's parameters or body did not pass validation."""
    detail: List[ValidationErrorItem]


# A 422 the route raises itself (a detail string) or FastAPI's own (a list)
Invalid = Union[ValidationErrors, ErrorDetail]

_ERROR_TEXT = {
    400: "Bad request",
    401: "Not signed in, or the session ended (reason says why)",
    403: "Not allowed: the feature is off or the call is refused",
    404: "Not found",
    409: "Conflict",
    413: "The upload is too large",
    422: "Invalid request",
    500: "Internal error. The details are in the container log.",
    502: "mailcow did not answer, or refused the request",
    503: "Not available right now",
}


def errors_as_json(document: Dict[str, Any]) -> None:
    """Errors are JSON on every route (FastAPI's HTTPException and validation
    handlers), but FastAPI documents an error model under the route's own
    response class, such as text/plain. Move those to application/json."""
    for operations in document.get("paths", {}).values():
        for operation in operations.values():
            for code, response in (operation.get("responses") or {}).items():
                content = response.get("content") or {}
                if code[:1] in ("4", "5") and len(content) == 1 and "application/json" not in content:
                    response["content"] = {"application/json": next(iter(content.values()))}


class CsvFile(Response):
    """For the documentation only: a route that returns a CSV download of its own
    gets response_class=CsvFile, so its answer is documented as text/csv, not JSON.
    The route's own response is sent unchanged."""
    media_type = "text/csv"


def documented(ok: Any, *, status: int = 200, description: str = "Success",
               errors: Optional[Dict[int, Any]] = None, media_type: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
    """The ``responses=`` value for a route: its answer and the errors it gives.

    ``errors`` maps a status to its model, or to None for ErrorDetail (ServerError for 500,
    NotSignedIn for 401). With
    ``ok`` None the answer keeps the route's response class (text, a file); ``media_type``
    then documents its body as text of that type.
    """
    out: Dict[int, Dict[str, Any]] = {status: {"description": description}}
    if ok is not None:
        out[status]["model"] = ok
    elif media_type:
        out[status]["content"] = {media_type: {"schema": {"type": "string"}}}
    for code, model in (errors or {}).items():
        default = {500: ServerError, 401: NotSignedIn}.get(code, ErrorDetail)
        out[code] = {"model": model or default, "description": _ERROR_TEXT.get(code, "Error")}
    return out
