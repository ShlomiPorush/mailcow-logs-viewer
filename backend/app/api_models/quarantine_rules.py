"""What the quarantine auto-rule calls return (routers/quarantine_rules.py)."""
from typing import Any, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class QuarantineRule(Fixed):
    id: int
    name: str
    match_type: str = Field(description="sender, sender_domain, recipient or subject")
    match_value: str
    is_regex: Optional[bool]
    action: str = Field(description="release or delete")
    enabled: Optional[bool]
    hit_count: int = Field(description="Messages the rule released or deleted")
    last_hit_at: Optional[str] = Field(description=TIME)
    notes: Optional[str]
    created_at: Optional[str] = Field(description=TIME)
    updated_at: Optional[str] = Field(description=TIME)


class QuarantineRuleList(Fixed):
    """Every rule: delete rules first, then newest first."""
    total: int
    data: List[QuarantineRule]


class QuarantineRuleDeleted(Fixed):
    success: bool = Field(description="true")
    message: str = Field(description="Such as Rule 'Block spam domain' deleted")


class QuarantineRuleLogEntry(Fixed):
    """One action the scheduled run took."""
    id: int
    rule_id: int
    rule_name: Optional[str] = Field(description="The rule's name at the time")
    action: str = Field(description="release or delete")
    quarantine_id: Optional[str] = Field(description="mailcow's quarantine item ID")
    sender: Optional[str]
    recipient: Optional[str]
    subject: Optional[str]
    matched_field: Optional[str] = Field(description="sender, sender_domain, recipient or subject")
    matched_value: Optional[str] = Field(description="The rule's value that matched")
    created_at: Optional[str] = Field(description=TIME)


class QuarantineRuleLogs(Fixed):
    """The actions, newest first."""
    total: int = Field(description="Actions that match, before limit and offset")
    data: List[QuarantineRuleLogEntry]


class QuarantineRuleMatch(Fixed):
    """A quarantined message and the first rule it matches."""
    quarantine_id: str = Field(description="mailcow's quarantine item ID")
    sender: Any = Field(description="As mailcow reports it")
    recipient: Any = Field(description="As mailcow reports it")
    subject: Any = Field(description="As mailcow reports it")
    rule_id: int
    rule_name: str
    action: str = Field(description="release or delete")
    rule_enabled: Optional[bool] = Field(description="false: the scheduled run would not act on it")


class QuarantineRuleTest(Fixed):
    """A dry run of every rule, enabled or not, against the quarantine now. Nothing is changed."""
    total_quarantine: int = Field(description="Messages in the quarantine")
    total_matches: int
    matches: List[QuarantineRuleMatch]
    message: str = Field(None, description="Only when nothing was tested: No rules to test, or Quarantine is "
                                           "empty")
