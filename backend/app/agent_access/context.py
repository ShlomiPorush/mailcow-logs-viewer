"""The marker an agent's /api call carries inside the app.

The dispatcher puts an AgentCall into the ASGI scope under SCOPE_KEY. A remote
client cannot set ASGI scope keys, so BasicAuthMiddleware admits a request
carrying one, and the policy guard (dispatch.enforce_agent_policy) decides
whether the route the router picked may run. Kept free of app imports so the
middleware can import it.
"""
from dataclasses import dataclass, field
from typing import Any, Optional

SCOPE_KEY = "mlv.agent"


@dataclass
class AgentCall:
    grant: Any                      # store.GrantInfo
    mode: str                       # 'read' (read_api) or 'write' (perform_action)
    # Filled in by the guard
    checked: bool = False
    path_template: Optional[str] = None
    area: Optional[str] = None
    denied: Optional[str] = None
    extra: dict = field(default_factory=dict)


def agent_call(scope) -> Optional[AgentCall]:
    value = scope.get(SCOPE_KEY)
    return value if isinstance(value, AgentCall) else None
