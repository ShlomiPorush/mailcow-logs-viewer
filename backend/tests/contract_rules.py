import json
from typing import Any, Dict, Optional, Tuple

from jsonschema import Draft202012Validator

APP_WIDE_STATUSES = {401, 403, 429}
MIDDLEWARE_401_SENTENCES = {b"Authentication required", b"Incorrect username or password"}


def success_responses(operation: Dict[str, Any]) -> Dict[str, Any]:
    return {code: r for code, r in (operation.get("responses") or {}).items() if code[:1] in ("2", "3")}


def says_something(schema: Dict[str, Any]) -> bool:
    if not schema:
        return False
    if schema.get("type") == "object" and not schema.get("properties") \
            and schema.get("additionalProperties", True) in (True, {}):
        return False
    return True


def is_documented(operation: Optional[Dict[str, Any]]) -> bool:
    if not operation:
        return False
    for code, response in success_responses(operation).items():
        content = response.get("content")
        if not content:
            if code.startswith("3") or code == "204":
                return True
            continue
        if any(says_something(media.get("schema") or {}) for media in content.values()):
            return True
    return False


def check_answer(operation: Dict[str, Any], components: Dict[str, Any], status: int,
                 content_type: str, body: Optional[bytes]) -> Tuple[str, Optional[str]]:
    if not is_documented(operation):
        return "skipped", "documents nothing yet"
    media = (content_type or "").split(";")[0].strip()
    if status == 500 and media != "application/json":
        return "skipped", "HTTP 500 from sign-in set up without a password"
    if status == 401 and media != "application/json" and body in MIDDLEWARE_401_SENTENCES:
        return "skipped", "HTTP 401 from sign-in"
    response = (operation.get("responses") or {}).get(str(status))
    if response is None:
        if status in APP_WIDE_STATUSES:
            return "skipped", f"HTTP {status} from sign-in or the origin guard"
        return "mismatch", f"HTTP {status}, a status its documentation does not list: {(body or b'')[:300]!r}"
    content = response.get("content") or {}
    if not content:
        if body:
            return "mismatch", f"HTTP {status} with a body, but its documentation says it has none"
        return "checked", None
    if body is None:
        return "skipped", "the browser could not read the body"
    if media not in content:
        return "mismatch", f"HTTP {status} as {media or 'no type'}, documented as {', '.join(content)}"
    schema = content[media].get("schema") or {}
    if media != "application/json" or not schema:
        return "checked", None
    try:
        data = json.loads(body)
    except ValueError:
        return "mismatch", f"HTTP {status} with a body that is not JSON: {body[:300]!r}"
    validator = Draft202012Validator({**schema, "components": components})
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if not errors:
        return "checked", None
    lines = [f"  at {'/'.join(str(p) for p in e.absolute_path) or '(top)'}: {e.message[:300]}" for e in errors[:5]]
    return "mismatch", f"HTTP {status} with an answer that does not match its documentation:\n" + "\n".join(lines)
