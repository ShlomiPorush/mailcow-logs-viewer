"""What the Messages routes return (routers/messages.py)."""
from typing import Any, Dict, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class StatusCounts(Fixed):
    """Messages per outcome; each count applies every filter except the outcome."""
    all: int
    delivered: int
    deferred: int
    bounced: int
    rejected: int
    spam: int
    discarded: int


class DirectionCounts(Fixed):
    """Messages per direction; each count applies every filter except the direction."""
    all: int
    inbound: int
    outbound: int
    internal: int


class MessageFacetsResponse(Fixed):
    """Counts for the Messages filters. Counts are messages, not delivery legs."""
    status: StatusCounts
    direction: DirectionCounts
    time: Dict[str, int] = Field(
        None, description="Only with `since`: an `all` count and one count per valid range name. "
                          "These ignore start_date and end_date.")


class NewMessagesResponse(Fixed):
    """How many messages matching the filters came after the list was read."""
    count: int = Field(description="New messages: a matching leg stored after after_id, and no leg "
                                   "of the same Message-ID stored before it")
    watermark: int = Field(description="The newest delivery leg now")


class MessageRow(Fixed):
    """One message in the list: the earliest leg that matched the filters."""
    correlation_key: str
    message_id: Optional[str]
    queue_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str] = Field(description="The leg's recipient")
    recipient_count: int = Field(description="The message's recipients across all its delivery legs: the "
                                             "details' recipient_count (excluded addresses left out); at least 1 "
                                             "when the leg names a recipient")
    subject: Optional[str]
    direction: Optional[str] = Field(description="inbound, outbound or internal")
    final_status: Optional[str] = Field(description="Such as delivered, deferred, bounced, rejected, spam or discarded")
    is_complete: Optional[bool]
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)
    dovecot_status: Optional[str] = Field(description="Outcome of the final LMTP hop: stored, discarded, rejected, "
                                                      "forwarded or failed; null without Dovecot information")
    dovecot_mailbox: Optional[str] = Field(description="The folder it was filed into")
    deliveries: int = Field(description="Delivery legs this message has in the database, including legs the "
                                        "filters did not match; a leg to or from an excluded address is not counted")
    spam_score: Optional[float]
    is_spam: Optional[bool]
    user: Optional[str] = Field(description="Authenticated sender, from Rspamd")
    ip: Optional[str] = Field(description="Client IP, from Rspamd")


class MessageListResponse(Fixed):
    """A page of messages, one row per message (legs are grouped by Message-ID)."""
    total: int = Field(description="Messages matching the filters, up to the watermark")
    page: int
    limit: int
    pages: int
    data: List[MessageRow]
    next_cursor: Optional[str] = Field(description="Pass as `cursor` for the next page; null on the last page")
    watermark: int = Field(description="The newest leg the list holds. Pass it as upto_id for the next pages, "
                                       "and as after_id to GET /api/messages/new")


QUEUE_ID_REUSED = ("Postfix gave this queue id to another message within 6 days, so only the message's cleanup "
                   "line is shown: no sender, recipients or outcome can be told apart")


class NoMessageIdRow(MessageRow):
    """A message without a usable Message-ID, described from its Postfix lines. correlation_key is
    noid-<id>: open it with GET /api/message/{correlation_key}/details. No subject, direction or spam
    score; user and ip come from the Postfix smtpd line."""
    queue_id_reused: bool = Field(description=QUEUE_ID_REUSED)


class NoMessageIdListResponse(Fixed):
    """A page of messages without a usable Message-ID, by the time Postfix received them."""
    total: int = Field(description="Messages matching the filters")
    data: List[NoMessageIdRow]
    next_cursor: Optional[str] = Field(description="Pass as `cursor` for the next page; null on the last page")
    time: Optional[Dict[str, int]] = Field(None, description="With since: an all count and one count per valid range")


class RelatedDelivery(Fixed):
    """Another delivery leg of the same Message-ID, such as a forward."""
    correlation_key: str
    sender: Optional[str]
    recipient: Optional[str]
    direction: Optional[str]
    final_status: Optional[str]
    first_seen: Optional[str] = Field(description=TIME)
    queue_id: Optional[str]
    dovecot_status: Optional[str]
    dovecot_mailbox: Optional[str]
    recipients: List[str] = Field(description="The recipients of this delivery, as the message dialog lists them: "
                                               "one address per recipient, an alias rather than the mailboxes it "
                                               "reached")


class RspamdScan(Fixed):
    """Rspamd's scan of the message."""
    time: Optional[str] = Field(description=TIME)
    score: Optional[float]
    required_score: Optional[float]
    action: Optional[str]
    symbols: Optional[Dict[str, Any]] = Field(description="The symbols as Rspamd reported them, by name")
    is_spam: Optional[bool]
    direction: Optional[str]
    ip: Optional[str]
    user: Optional[str]
    has_auth: Optional[bool]
    size: Optional[int]
    country_code: Optional[str]
    country_name: Optional[str]
    city: Optional[str]
    asn: Optional[str]
    asn_org: Optional[str]


class DovecotLine(Fixed):
    """A raw Dovecot LMTP line about this message, while raw log retention keeps it."""
    time: Optional[str] = Field(description=TIME)
    priority: Optional[str]
    message: Optional[str]
    verdict: Optional[str]
    recipient: Optional[str]
    mailbox: Optional[str]


class DovecotOutcome(Fixed):
    """The outcome of the final LMTP hop."""
    status: Optional[str] = Field(description="stored, discarded, rejected, forwarded or failed")
    mailbox: Optional[str]
    detail: Optional[str] = Field(description="The reject reason, forward target or storage error")
    logs: List[DovecotLine]


class PostfixLine(Fixed):
    """One Postfix log line of the message's queue."""
    time: Optional[str] = Field(description=TIME)
    program: Optional[str]
    priority: Optional[str]
    message: Optional[str]
    status: Optional[str]
    relay: Optional[str]
    delay: Optional[float]
    dsn: Optional[str]


class PostfixLineWithRecipient(PostfixLine):
    recipient: Optional[str]


class NetfilterEvent(Fixed):
    """A Netfilter event for the Rspamd client IP, within an hour of the scan."""
    time: Optional[str] = Field(description=TIME)
    ip: Optional[str]
    username: Optional[str]
    auth_method: Optional[str]
    action: Optional[str]
    attempts_left: Optional[int]
    message: Optional[str]


class PostfixClient(Fixed):
    """The client that handed a message to Postfix, from its smtpd "client=" line."""
    ip: Optional[str]
    host: Optional[str] = Field(description="The client's name as Postfix resolved it, `unknown` without one")
    user: Optional[str] = Field(description="The signed-in user, when the client logged in")
    country_code: Optional[str] = Field(None, description="Where the address is (MaxMind GeoIP), null without GeoIP")
    country_name: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None


class MessageDetailsResponse(Fixed):
    """One delivery leg with its Postfix, Rspamd, Dovecot and Netfilter logs."""
    correlation_key: str
    message_id: Optional[str]
    queue_id: Optional[str]
    sender: Optional[str]
    recipient: Optional[str] = Field(description="The leg's recipient")
    recipients: List[str] = Field(description="Every recipient, from Rspamd, else from the Postfix lines")
    recipient_count: int = Field(description="How many recipients the whole message has, as the message dialog "
                                             "counts them: those of this delivery and of the related deliveries, "
                                             "one per address in any case, an alias once however many mailboxes "
                                             "it reached, addresses only Postfix logged included; at least 1 when "
                                             "the leg names a recipient. It can differ from the length of "
                                             "`recipients`, which lists this delivery's only")
    subject: Optional[str] = Field(description="Taken from another leg of the same message when this one has none")
    direction: Optional[str]
    final_status: Optional[str]
    is_complete: Optional[bool]
    first_seen: Optional[str] = Field(description=TIME)
    last_seen: Optional[str] = Field(description=TIME)
    related_deliveries: List[RelatedDelivery] = Field(description="Other legs of the same Message-ID, by first_seen; "
                                                                  "empty for most messages")
    rspamd: Optional[RspamdScan] = Field(description="Null when the message was not scanned")
    dovecot: Optional[DovecotOutcome] = Field(description="Null without Dovecot information")
    postfix_by_recipient: Dict[str, List[PostfixLine]] = Field(
        description="The Postfix lines by recipient; lines that belong to no recipient are under `_system`")
    postfix: List[PostfixLineWithRecipient]
    netfilter: List[NetfilterEvent] = Field(description="At most 100 events, newest first")
    client: Optional[PostfixClient] = Field(
        None, description="For a message without a Message-ID (a noid- key): who handed it to Postfix, from the "
                          "smtpd line. Null otherwise; a scanned message has these in `rspamd`")
    queue_id_reused: Optional[bool] = Field(
        None, description="For a message without a Message-ID (a noid- key): " + QUEUE_ID_REUSED + ". Null otherwise")
