from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response


class Fixed(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorDetail(Fixed):
    """An error: what went wrong, in words."""
    detail: str = Field(description="What went wrong")


class SessionEnded(Fixed):
    """A session cookie that a limit ended; the X-Session-End header carries the reason too."""
    detail: str = Field(description="What happened")
    reason: str = Field(description="session_expired (the longest session), session_idle (inactivity) or "
                                    "access_changed (the person's account changed or no longer gives access)")


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
    for operations in document.get("paths", {}).values():
        for operation in operations.values():
            for code, response in (operation.get("responses") or {}).items():
                content = response.get("content") or {}
                if code[:1] in ("4", "5") and len(content) == 1 and "application/json" not in content:
                    response["content"] = {"application/json": next(iter(content.values()))}


class CsvFile(Response):
    media_type = "text/csv"


def documented(ok: Any, *, status: int = 200, description: str = "Success",
               errors: Optional[Dict[int, Any]] = None, media_type: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {status: {"description": description}}
    if ok is not None:
        out[status]["model"] = ok
    elif media_type:
        out[status]["content"] = {media_type: {"schema": {"type": "string"}}}
    for code, model in (errors or {}).items():
        default = {500: ServerError, 401: NotSignedIn}.get(code, ErrorDetail)
        out[code] = {"model": model or default, "description": _ERROR_TEXT.get(code, "Error")}
    return out
