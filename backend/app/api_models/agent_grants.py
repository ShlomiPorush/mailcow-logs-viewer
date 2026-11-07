"""What the consent page and Settings > Agents calls return (agent_access/consent.py).

For people only: an agent's own calls never reach these routes. Its own calls
are described in agents.py.
"""
from typing import Dict, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class AgentAreaInfo(Fixed):
    """An area of the app an agent can be allowed to view, and act in."""
    id: str
    label: str
    view: str = Field(description="What View allows")
    act: str = Field(description="What Act allows; empty when the area has no actions")


class AgentPeriod(Fixed):
    """A period access can last, up to the configured maximum."""
    days: float = Field(description="1/24 is one hour")
    label: str


class ConsentClient(Fixed):
    """The agent that asks."""
    declared_name: str = Field(description="The name the agent gave itself")
    publisher: Optional[str] = Field(description="The host of a client ID document; null for other agents")
    kind: str = Field(description="dcr, cimd or device")
    redirect_uri: Optional[str] = Field(description="Where the answer goes; null for an agent that connects with a code")
    user_code: Optional[str] = Field(description="An agent that connects with a code: the code it shows, as "
                                                 "XXXX-XXXX, to compare; null otherwise")


class ConsentRequest(Fixed):
    """An agent's open access request, for the consent page."""
    client: ConsentClient
    areas: List[AgentAreaInfo]
    preselected_views: List[str] = Field(description="The areas whose View starts ticked")
    periods: List[AgentPeriod]
    default_days: float
    app_title: str
    signed_in_as: Optional[str] = Field(description="The signed-in person; null when the session does not name one")


class ConsentDone(Fixed):
    """An agent that connects with a code was answered; it collects its access itself."""
    done: bool = Field(description="true")


class ConsentRedirect(Fixed):
    """Where to send the browser: back to the agent, with a code or with access_denied."""
    redirect: str


class AgentGrantRow(Fixed):
    """A connected agent, or one whose access ended in the last 30 days."""
    id: int
    name: str = Field(description="The name the person gave it")
    declared_name: str = Field(description="The name the agent gave itself")
    publisher: Optional[str]
    kind: str = Field(description="dcr, cimd or device")
    areas: Dict[str, str] = Field(description="area id -> view or act")
    approved_by: Optional[str]
    created_at: str = Field(description=TIME)
    expires_at: str = Field(description=TIME)
    last_used_at: Optional[str] = Field(description=TIME)
    ended_at: Optional[str] = Field(description="When access was disconnected or ran out, " + TIME + "; null while connected")
    end_reason: Optional[str] = Field(description="Such as disconnected, sign_in_changed or expired; null while connected")
    state: str = Field(description="connected, disconnected or expired")
    version: str = Field(description="Send it with a change, so a change made meanwhile is not undone")


class AgentsOverview(Fixed):
    """Settings > Agents: whether agents can connect, and the agents."""
    live: bool = Field(description="Agents can connect")
    problem: Optional[str] = Field(description="Why agents cannot connect: no_sign_in, off, no_url or bad_url; "
                                               "null when live")
    enabled: bool = Field(description="The Agent access switch")
    url: str = Field(description="The app address agents use (AGENT_ACCESS_URL); may be empty")
    mcp_url: Optional[str] = Field(description="The MCP server address; null when not live")
    skill_sentence: Optional[str] = Field(description="What to tell an agent that runs commands; null when not live")
    mcp_sentence: Optional[str] = Field(description="What to tell an MCP app; null when not live")
    max_days: int = Field(description="The longest access a person can give")
    areas: List[AgentAreaInfo]
    periods: List[AgentPeriod]
    agents: List[AgentGrantRow] = Field(description="Connected agents first, then newest first")


class AgentChanged(Fixed):
    changed: int = Field(description="1")


class AgentsDisconnected(Fixed):
    disconnected: int = Field(description="Agents this call disconnected")


class AgentActivityRow(Fixed):
    at: str = Field(description=TIME)
    event: str = Field(description="Such as grant_created, grant_changed, grant_revoked, call or denied")
    tool: Optional[str]
    method: Optional[str]
    path: Optional[str]
    http_status: Optional[int]
    outcome: Optional[str] = Field(description="ok, error, accepted or denied")
    detail: Optional[str]


class AgentActivity(Fixed):
    """An agent's last 50 events, newest first."""
    activity: List[AgentActivityRow]
