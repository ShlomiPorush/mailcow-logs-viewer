"""Report, export and email modules ask app_time for every zone question.

A bare datetime.now() is the container's local wall time, fromtimestamp()
without a zone and .timestamp() on a stored (naive UTC) value read the
container's zone too, and settings.tz bypasses the fallback for an unknown
zone. None of them may appear here: windows and comparisons are UTC, days,
labels, file names and emails are in the app time zone (app/app_time.py).
"""
import ast
import pathlib

import pytest

APP = pathlib.Path(__file__).resolve().parent.parent / "app"
MODULES = [
    "routers/dmarc.py",
    "routers/export.py",
    "routers/mailbox_stats.py",
    "routers/rate_limits.py",
    "routers/reporting.py",
    "routers/suppressions.py",
    "services/email_layout.py",
]


def _offences(source: str):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == "tz" and getattr(node.value, "id", None) == "settings":
            yield node.lineno, "settings.tz"
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        name = node.func.attr
        if name == "now" and not node.args and not node.keywords:
            yield node.lineno, "now() without a zone"
        elif name == "fromtimestamp" and len(node.args) < 2 and not node.keywords:
            yield node.lineno, "fromtimestamp() without a zone"
        elif name in ("timestamp", "utcfromtimestamp"):
            yield node.lineno, f".{name}()"


@pytest.mark.parametrize("module", MODULES)
def test_no_container_clock_and_no_direct_zone_setting(module):
    source = (APP / module).read_text(encoding="utf-8")
    found = [f"{module}:{line} {what}" for line, what in _offences(source)]
    assert not found, "use app.app_time instead: " + ", ".join(found)
