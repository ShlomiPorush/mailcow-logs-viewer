"""The suppression sync must not write the Rspamd map when it could not read it.

The map holds the admin's own entries above the managed section. The sync
used to go on with empty content when the read failed, and its write then
replaced the whole map with the managed section only.
"""
import asyncio

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.mailcow_api import MailcowAPIError  # noqa: E402
from app.routers import suppressions as sup  # noqa: E402


@pytest.mark.parametrize("failing", ["find", "get"])
def test_a_map_that_could_not_be_read_is_not_written(monkeypatch, failing):
    writes = []

    async def fake_find(name):
        if failing == "find":
            raise MailcowAPIError("Rspamd API request failed with status 502")
        return 7

    async def fake_get(map_id):
        raise MailcowAPIError("Rspamd API request failed with status 502")

    async def fake_edit(name, content):
        writes.append(content)

    monkeypatch.setattr(sup.mailcow_api, "find_rspamd_map_id", fake_find)
    monkeypatch.setattr(sup.mailcow_api, "get_rspamd_map_content", fake_get)
    monkeypatch.setattr(sup.mailcow_api, "edit_rspamd_map", fake_edit)

    with pytest.raises(MailcowAPIError):
        asyncio.run(sup.sync_suppressions_to_rspamd(db=None))
    assert writes == []
