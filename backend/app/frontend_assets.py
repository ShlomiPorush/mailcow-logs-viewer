import hashlib
import os
import re
from functools import lru_cache

_ASSET_REF = re.compile(r'(/static/([A-Za-z0-9_./-]+\.(?:css|js)))\?v=[A-Za-z0-9_.-]*')


def stamp_asset_versions(html: str, frontend_dir: str) -> str:
    root = os.path.realpath(frontend_dir)

    def stamp(match: re.Match) -> str:
        path = os.path.realpath(os.path.join(root, match.group(2)))
        if not path.startswith(root + os.sep):
            return match.group(0)
        try:
            digest = _file_digest(path, os.stat(path).st_mtime_ns)
        except OSError:
            return match.group(0)
        return f"{match.group(1)}?v={digest}"

    return _ASSET_REF.sub(stamp, html)


@lru_cache(maxsize=256)
def _file_digest(path: str, mtime_ns: int) -> str:
    with open(path, 'rb') as asset:
        return hashlib.sha256(asset.read()).hexdigest()[:12]
