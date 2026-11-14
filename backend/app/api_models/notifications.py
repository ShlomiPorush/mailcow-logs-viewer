"""What the notification destination calls return (routers/notifications.py)."""
from typing import Any, Dict, List, Optional

from pydantic import Field

from . import Fixed

TIME = "UTC, ISO 8601 with Z"


class NotificationField(Fixed):
    """A setting the service type needs; the form shows only these."""
    key: str = Field(description="Its name in config")
    label: str
    type: str = Field(description="url or text")
    required: bool
    secret: bool = Field(None, description="Only for a secret: true. Masked once saved")
    placeholder: str = Field(None)
    default: str = Field(None, description="Only for the ntfy server URL: https://ntfy.sh")


class NotificationServiceType(Fixed):
    id: str = Field(description="slack, discord, telegram, ntfy, gotify or webhook")
    label: str
    help: str = Field(description="Where to get the settings")
    fields: List[NotificationField]


class NotificationAlertType(Fixed):
    id: str = Field(description="security, blacklist, dns_changes or dmarc_errors")
    label: str
    description: str = Field(description="Which alerts it covers")


class NotificationTypes(Fixed):
    """The service types and the alert types a destination can subscribe to."""
    types: List[NotificationServiceType]
    alert_types: List[NotificationAlertType]


class NotificationChannel(Fixed):
    """A destination, secrets masked."""
    id: int
    name: str
    channel_type: str = Field(description="slack, discord, telegram, ntfy, gotify or webhook")
    config: Dict[str, Any] = Field(description="The type's fields by key, as saved; a saved secret is ********")
    alert_types: List[str] = Field(description="The alert types it receives; empty is every alert")
    enabled: bool
    last_status: Optional[str] = Field(description="success or failed; null before the first delivery")
    last_error: Optional[str] = Field(description="Why the last delivery failed, secrets removed, up to 500 "
                                                  "characters")
    last_sent_at: Optional[str] = Field(description=TIME)


class NotificationChannels(Fixed):
    channels: List[NotificationChannel] = Field(description="In the order they were added")


class NotificationChannelDeleted(Fixed):
    status: str = Field(description="success")


class NotificationTest(Fixed):
    """The outcome of a test notification."""
    success: bool = Field(description="The service accepted it")
    logs: List[str] = Field(description="What happened, line by line; the last line says delivered or why not")
