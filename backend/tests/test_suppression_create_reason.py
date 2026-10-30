"""Every reason the Add Suppression dialog offers is accepted."""
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.routers.suppressions import SuppressionCreateRequest

DIALOG = Path(__file__).resolve().parents[2] / "frontend" / "spam_filter.js"


def _dialog_reasons():
    source = DIALOG.read_text(encoding="utf-8")
    select = re.search(r'<select id="new-suppression-reason".*?</select>', source, re.S).group(0)
    return re.findall(r'<option value="([^"]+)"', select)


def test_dialog_offers_deferred_stuck():
    assert "deferred_stuck" in _dialog_reasons()


@pytest.mark.parametrize("reason", _dialog_reasons())
def test_every_dialog_reason_is_accepted(reason):
    body = SuppressionCreateRequest(email="user@example.com", reason=reason)
    assert body.reason == reason


def test_unknown_reason_is_still_refused():
    with pytest.raises(ValidationError):
        SuppressionCreateRequest(email="user@example.com", reason="whatever")
