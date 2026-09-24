"""Every setting that can be edited from the UI must have a place on the Settings page.

The backend decides which settings are editable (EDITABLE_SETTING_KEYS); the
Settings page only renders the keys listed in its tab definitions in
frontend/settings.js (groups: [{ label, keys: [...] }]). A key missing from
those tabs is editable in theory but unreachable in practice, which is how an
option silently disappears when the page is reorganised or redesigned.
"""
import re
from pathlib import Path

from app.config import EDITABLE_SETTING_KEYS

SETTINGS_JS = Path(__file__).resolve().parents[2] / "frontend" / "settings.js"


def _settings_page_keys() -> set:
    text = SETTINGS_JS.read_text(encoding="utf-8")
    keys = set()
    for group in re.findall(r"\bkeys:\s*\[([^\]]*)\]", text):
        keys.update(re.findall(r"'([^']+)'", group))
    return keys


def test_every_editable_setting_is_on_the_settings_page():
    missing = sorted(EDITABLE_SETTING_KEYS - _settings_page_keys())
    assert not missing, (
        "editable settings that no Settings tab shows (add them to a tab in frontend/settings.js): "
        + ", ".join(missing)
    )
