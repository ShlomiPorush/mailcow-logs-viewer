"""The skill for agents that run commands, served by the app with its address filled in.

The person pastes one sentence to the agent (Settings > Agents). It points to
/agents/skill/, a short install note; the agent downloads the files listed
there, reads SKILL.md and connects with a code (oauth.py, RFC 8628). Public
(the files hold no secret), never cached, and only while agent access is live
on an https address (or this computer): an agent runs what it downloads here.
Only the files in FILES are served, from this version of the app.
"""
import hashlib
import re
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response

from . import live

router = APIRouter(include_in_schema=False)

SKILL_DIR = Path(__file__).parent / "skill_files"
SKILL_NAME = "mailcow-logs"
FILES: Dict[str, str] = {
    "SKILL.md": "text/markdown; charset=utf-8",
    "scripts/mailcow-logs": "text/plain; charset=utf-8",
    "scripts/mailcow-logs.mjs": "text/javascript; charset=utf-8",
    "scripts/mailcow-logs.ps1": "text/plain; charset=utf-8",
    "scripts/mailcow-logs.sh": "text/plain; charset=utf-8",
}
PLACEHOLDER = "__MAILCOW_LOGS_URL__"
VERSION_PLACEHOLDER = "__MAILCOW_LOGS_SKILL_VERSION__"
# The canonical address (live.normalize_base_url) is only ever this shape; it
# goes into JavaScript, PowerShell and sh source, so nothing else is accepted
_SAFE_URL = re.compile(r"^https?://(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:[0-9]{1,5})?$")
_HEADERS = {"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"}
_cache: Dict[str, str] = {}


def _base() -> Optional[str]:
    if not live.is_live():
        return None
    base = live.issuer()
    return base if _SAFE_URL.match(base) else None


def _read(name: str) -> Optional[str]:
    text = _cache.get(name)
    if text is None:
        try:
            text = (SKILL_DIR / name).read_text(encoding="utf-8")
        except OSError:
            return None
        _cache[name] = text
    return text


def skill_version() -> str:
    """A short hash of the skill's files as shipped: the scripts send it, and the app
    tells an agent with another one to install the skill again (rest.py, access)."""
    version = _cache.get("__version__")
    if version is None:
        digest = hashlib.sha256()
        for name in sorted(FILES):
            digest.update(name.encode("utf-8") + b"\0" + (_read(name) or "").encode("utf-8") + b"\0")
        version = digest.hexdigest()[:12]
        _cache["__version__"] = version
    return version


def sentence(base: str) -> str:
    """The sentence the person pastes to the agent (shown in Settings > Agents)."""
    return (f"Install the {SKILL_NAME} skill into your personal skills folder as described at "
            f"{base}/agents/skill/, then connect to mailcow Logs Viewer.")


def install_note(base: str) -> str:
    files = "\n".join(f"- {base}/agents/skill/{name} -> {SKILL_NAME}/{name}" for name in FILES)
    return f"""# Install the {SKILL_NAME} skill

Download these files into a folder named `{SKILL_NAME}` in your personal skills folder (Claude Code:
`~/.claude/skills/`, or `$CLAUDE_CONFIG_DIR/skills/` when it is set; Codex: `~/.codex/skills/`). If a
`{SKILL_NAME}` skill for another address is already there, use the folder `{SKILL_NAME}-{_host(base)}` instead
and never change the address of the existing one.

{files}

On Linux and macOS, make `scripts/{SKILL_NAME}` and `scripts/{SKILL_NAME}.sh` executable (`chmod +x`).

When you install again over an older copy, replace only these files and keep the folder's `.install-id` file. It ties
this install to its connection, so nothing has to be approved again.

Then read `{SKILL_NAME}/SKILL.md` now, without waiting for skills to reload, and follow its Connecting steps.
Show the person the link and the code that `{SKILL_NAME} connect` prints in the reply that ends your turn.
"""


def mcp_sentence(base: str) -> str:
    """The sentence a person pastes to an agent that should connect over MCP (Settings > Agents > MCP)."""
    return (f"Connect yourself to mailcow Logs Viewer over MCP as described at {base}/agents/mcp/, "
            "then tell me what to approve.")


def mcp_note(base: str) -> str:
    """How to add this app as an MCP server, for an agent or a person, in the common clients."""
    url = f"{base}/mcp"
    return f"""# Connect to mailcow Logs Viewer over MCP

MCP server URL: `{url}` (Streamable HTTP). There is no key. The client signs in with OAuth, and a person
approves it in a browser on the same computer, choosing what it may view or act on and for how long.

Add the server the way your client adds remote MCP servers:

- Claude Code: `claude mcp add --transport http mailcow {url}`. Then sign in with `/mcp` (choose mailcow,
  then Authenticate) or `claude mcp login mailcow`.
- Codex: `codex mcp add mailcow --url {url}`. If the browser does not open, run `codex mcp login mailcow`.
- Cursor: in `~/.cursor/mcp.json`, add `"mailcow": {{"url": "{url}"}}` under `"mcpServers"`.
- VS Code: in `.vscode/mcp.json`, add `"mailcow": {{"type": "http", "url": "{url}"}}` under `"servers"`.
- Claude Desktop or claude.ai: Settings, Connectors, Add custom connector, with this URL. The app must be
  reachable from the internet for this.
- Any other client: add a remote (HTTP) MCP server with this URL.

The first time, a browser opens on this computer. Ask the person to sign in, check who is asking, choose
what you may view or act on, and approve. Most clients load the new tools only in a new session.

If the person cannot approve in a browser on this computer, for example because they are on a phone, and you
can run commands, connect with the skill instead: {base}/agents/skill/
"""


@router.get("/agents/mcp")
@router.get("/agents/mcp/")
def mcp_instructions():
    base = _base()
    if base is None:
        return JSONResponse({"error": "not_available",
                             "message": "Agent access is off on this server. Turn it on in Settings > Agents."},
                            status_code=404, headers=_HEADERS)
    return Response(mcp_note(base), media_type="text/markdown; charset=utf-8", headers=_HEADERS)


def _host(base: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "-", base.split("://", 1)[-1].lower())


@router.get("/agents/skill")
def skill_root_redirect():
    return RedirectResponse("/agents/skill/", status_code=301)


@router.get("/agents/skill/{name:path}")
def skill_file(name: str):
    base = _base()
    if base is None:
        return JSONResponse({"error": "not_available",
                             "message": "Agents install the skill from an https address while agent access is on. "
                                        "Turn it on in Settings > Agents."}, status_code=404, headers=_HEADERS)
    if name == "":
        if _read("SKILL.md") is None:
            return JSONResponse({"error": "not_found", "message": "This build has no agent skill."},
                                status_code=404, headers=_HEADERS)
        return Response(install_note(base), media_type="text/markdown; charset=utf-8", headers=_HEADERS)
    kind = FILES.get(name)
    text = _read(name) if kind else None
    if text is None:
        return JSONResponse({"error": "not_found"}, status_code=404, headers=_HEADERS)
    text = text.replace(PLACEHOLDER, base).replace(VERSION_PLACEHOLDER, skill_version())
    return PlainTextResponse(text, media_type=kind, headers=_HEADERS)
