"""Tests for bounded decompression (decompression-bomb protection)."""
import gzip
import io
import zipfile

import pytest

from app.services.safe_decompress import (
    DecompressionLimitError,
    MAX_DECOMPRESSED_BYTES,
    gzip_decompress_limited,
    zip_read_limited,
)


def _zip_with(name: str, payload: bytes) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, payload)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_small_gzip_roundtrip():
    data = b"hello world" * 1000
    assert gzip_decompress_limited(gzip.compress(data)) == data


def test_gzip_bomb_rejected():
    bomb = gzip.compress(b"\x00" * (MAX_DECOMPRESSED_BYTES + 1024 * 1024))
    # the compressed bomb is tiny but expands past the cap
    assert len(bomb) < 1024 * 1024
    with pytest.raises(DecompressionLimitError):
        gzip_decompress_limited(bomb)


def test_gzip_custom_limit():
    data = b"x" * 2048
    with pytest.raises(DecompressionLimitError):
        gzip_decompress_limited(gzip.compress(data), max_bytes=1024)


def test_small_zip_member_roundtrip():
    payload = b"<feedback></feedback>"
    with _zip_with("report.xml", payload) as zf:
        assert zip_read_limited(zf, "report.xml") == payload


def test_zip_bomb_rejected_by_declared_size():
    with _zip_with("report.xml", b"\x00" * (MAX_DECOMPRESSED_BYTES + 1024 * 1024)) as zf:
        with pytest.raises(DecompressionLimitError):
            zip_read_limited(zf, "report.xml")


def test_zip_bomb_rejected_while_reading_with_custom_limit():
    # declared size below default cap, but above a custom limit
    with _zip_with("report.xml", b"\x00" * 4096) as zf:
        with pytest.raises(DecompressionLimitError):
            zip_read_limited(zf, "report.xml", max_bytes=1024)
