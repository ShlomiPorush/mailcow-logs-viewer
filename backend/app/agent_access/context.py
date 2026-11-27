from dataclasses import dataclass, field
from typing import Any, Optional

SCOPE_KEY = "mlv.agent"


@dataclass
class AgentCall:
    grant: Any
    mode: str
    checked: bool = False
    path_template: Optional[str] = None
    area: Optional[str] = None
    denied: Optional[str] = None
    extra: dict = field(default_factory=dict)


def agent_call(scope) -> Optional[AgentCall]:
    value = scope.get(SCOPE_KEY)
    return value if isinstance(value, AgentCall) else None
