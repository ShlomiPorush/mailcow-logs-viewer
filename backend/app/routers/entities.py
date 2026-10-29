"""
The entity card: what the app stores about one IP address, email address or
domain, opened from any page (services/entity_summary.py).

The value is a query parameter (an address may hold '/' or '%'); it is read
by services/entity_values.py, and a value that is not one IP, address or
domain answers 422 with what to change. Not offered to AI agents
(agent_access/scopes.py EXCLUDED).
"""
import logging
from typing import Optional

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..api_models import Invalid, documented
from ..api_models import entities as m
from ..database import get_db
from ..mailcow_api import mailcow_api
from ..services import entity_summary, entity_values
from ..utils import RangeEnd, RangeStart, internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

# How long the card waits for mailcow's Fail2ban lists before it shows them as unknown
FAIL2BAN_WAIT_SECONDS = 5

_VALUE_MAX = 1024
_START = "Start of the range (an ISO instant or a YYYY-MM-DD day). Default: 7 days before the end"
_END = "End of the range. Default: now. The range is 90 days at most"


def _read(kind: str, value: str):
    try:
        if kind == "address":
            return entity_values.normalize_address(value)
        return entity_values.normalize(kind, value)
    except entity_values.InvalidValue as e:
        raise HTTPException(status_code=422, detail=str(e))


def _range(start_date, end_date):
    try:
        return entity_summary.resolve_range(start_date, end_date)
    except entity_values.InvalidValue as e:
        raise HTTPException(status_code=422, detail=str(e))


def _read_fail2ban():
    """mailcow's Fail2ban answer, or None when it does not answer in time. Runs
    the client on the event loop from this worker thread."""
    async def read():
        with anyio.move_on_after(FAIL2BAN_WAIT_SECONDS):
            return await mailcow_api.get_fail2ban()
        return None
    return anyio.from_thread.run(read)


@router.get("/entities/ip", responses=documented(m.IpCard, errors={422: Invalid, 500: None}))
def get_ip_card(
    value: str = Query(..., max_length=_VALUE_MAX, description="One IPv4 or IPv6 address (not a network)"),
    start_date: Optional[RangeStart] = Query(None, description=_START),
    end_date: Optional[RangeEnd] = Query(None, description=_END),
    db: Session = Depends(get_db),
):
    """
    What is stored about one IP address: its messages, security events and
    bans, Fail2ban list state, protection catches, devices last seen from it,
    DMARC records naming it for every domain, the last blocklist check and its
    place. Each source says whether it is ok, off or failed.
    """
    ip = _read("ip", value)
    start, end = _range(start_date, end_date)
    try:
        return entity_summary.ip_summary(db, ip, start, end, _read_fail2ban)
    except Exception as e:
        logger.error(f"Error building the IP card: {e}")
        raise internal_error(e)


@router.get("/entities/address", responses=documented(m.AddressCard, errors={422: Invalid, 500: None}))
def get_address_card(
    value: str = Query(..., max_length=_VALUE_MAX, description="One email address or mailbox"),
    start_date: Optional[RangeStart] = Query(None, description=_START),
    end_date: Optional[RangeEnd] = Query(None, description=_END),
    db: Session = Depends(get_db),
):
    """
    What is stored about one email address or mailbox: its messages sent and
    received, security events and protection catches naming it, its devices,
    its suppression entry and whether it is a mailbox or alias here.
    """
    address, display = _read("address", value)
    start, end = _range(start_date, end_date)
    try:
        return entity_summary.address_summary(db, address, display, start, end)
    except Exception as e:
        logger.error(f"Error building the address card: {e}")
        raise internal_error(e)


@router.get("/entities/domain", responses=documented(m.DomainCard, errors={422: Invalid, 500: None}))
def get_domain_card(
    value: str = Query(..., max_length=_VALUE_MAX, description="One domain; an IDN in Unicode or ASCII"),
    start_date: Optional[RangeStart] = Query(None, description=_START),
    end_date: Optional[RangeEnd] = Query(None, description=_END),
    db: Session = Depends(get_db),
):
    """
    What is stored about one domain: messages from and to its addresses,
    security events and devices of its accounts, its DMARC reports, its
    suppression entry, its mailboxes and its stored DNS check.
    """
    domain = _read("domain", value)
    start, end = _range(start_date, end_date)
    try:
        return entity_summary.domain_summary(db, domain, start, end)
    except Exception as e:
        logger.error(f"Error building the domain card: {e}")
        raise internal_error(e)
