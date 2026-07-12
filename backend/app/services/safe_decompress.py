"""
Bounded decompression helpers for report attachments.

DMARC / TLS-RPT reports are small (typically well under 1 MB uncompressed).
These helpers read gzip/zip streams in chunks and abort once a hard size
cap is exceeded, so a malicious "report" crafted as a decompression bomb
(emailed to the DMARC mailbox or uploaded via the UI) cannot exhaust
container memory.
"""
import gzip
import zipfile
import logging
from io import BytesIO

logger = logging.getLogger(__name__)

# Hard cap on decompressed report size. Real aggregate reports are < 1 MB;
# 50 MB leaves generous headroom for very large senders.
MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024

# Hard cap on the compressed input itself (upload / mail attachment).
MAX_COMPRESSED_BYTES = 10 * 1024 * 1024

_CHUNK_SIZE = 1024 * 1024


class DecompressionLimitError(Exception):
    """Decompressed content exceeded the allowed size limit."""


def _read_limited(stream, max_bytes: int, source: str) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = stream.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise DecompressionLimitError(
                f"{source}: decompressed content exceeds {max_bytes // (1024 * 1024)} MB limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def gzip_decompress_limited(data: bytes, max_bytes: int = MAX_DECOMPRESSED_BYTES,
                            source: str = "gzip") -> bytes:
    """Decompress gzip data, raising DecompressionLimitError past max_bytes."""
    with gzip.open(BytesIO(data), "rb") as f:
        return _read_limited(f, max_bytes, source)


def zip_read_limited(zf: zipfile.ZipFile, name: str,
                     max_bytes: int = MAX_DECOMPRESSED_BYTES,
                     source: str = "zip") -> bytes:
    """Read a single zip member, raising DecompressionLimitError past max_bytes.

    The declared file_size in the ZIP header can be forged, so the limit is
    enforced while reading, not just against the header.
    """
    info = zf.getinfo(name)
    if info.file_size > max_bytes:
        raise DecompressionLimitError(
            f"{source}:{name}: declared size {info.file_size} exceeds "
            f"{max_bytes // (1024 * 1024)} MB limit"
        )
    with zf.open(name, "r") as f:
        return _read_limited(f, max_bytes, f"{source}:{name}")
