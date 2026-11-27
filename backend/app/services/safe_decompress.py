import gzip
import zipfile
import logging
from io import BytesIO

logger = logging.getLogger(__name__)

MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024

MAX_COMPRESSED_BYTES = 10 * 1024 * 1024

_CHUNK_SIZE = 1024 * 1024


class DecompressionLimitError(Exception):
    pass


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
    with gzip.open(BytesIO(data), "rb") as f:
        return _read_limited(f, max_bytes, source)


def zip_read_limited(zf: zipfile.ZipFile, name: str,
                     max_bytes: int = MAX_DECOMPRESSED_BYTES,
                     source: str = "zip") -> bytes:
    info = zf.getinfo(name)
    if info.file_size > max_bytes:
        raise DecompressionLimitError(
            f"{source}:{name}: declared size {info.file_size} exceeds "
            f"{max_bytes // (1024 * 1024)} MB limit"
        )
    with zf.open(name, "r") as f:
        return _read_limited(f, max_bytes, f"{source}:{name}")
