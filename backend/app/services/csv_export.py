"""Spreadsheet-oriented CSV serialization shared by every download endpoint."""
import csv
import io
import math
import unicodedata
from itertools import chain
from fastapi import Depends, HTTPException
from fastapi.responses import Response, StreamingResponse

from ..database import get_db

# Suppression exports carry the exact escaped field names for lossless re-import.
CSV_ESCAPE_COLUMN = "_csv_escape_v1"
CSV_QUERY_BATCH_SIZE = 500


def get_csv_db(db=Depends(get_db)):
    """Close export cursors before the parent dependency closes the session."""
    try:
        yield db
    finally:
        for rows in db.info.pop("csv_export_iterators", ()):
            rows.close()


def csv_query_rows(query, *, allow_empty=False):
    """Fetch bounded batches; the request-scoped dependency owns the session.

    Peek before sending headers so empty log exports retain their HTTP 404.
    FastAPI closes the session after the response, including on disconnect.
    """
    rows = iter(query.yield_per(CSV_QUERY_BATCH_SIZE))
    query.session.info.setdefault("csv_export_iterators", []).append(rows)
    first = next(rows, None)
    if first is None:
        if not allow_empty:
            raise HTTPException(status_code=404, detail="No data to export")
        return iter(())
    return chain((first,), rows)


def escape_csv_text(value):
    """Protect text cells without converting numbers or changing stored data."""
    if not isinstance(value, str) or not value:
        return value
    # Normalize only for detection, preserving the original spelling in output.
    normalized = unicodedata.normalize("NFKC", value)
    first = next((char for char in normalized
                  if not (char.isspace() or ord(char) < 33 or char in "\x7f\ufeff\u200b")), "")
    if ord(value[0]) < 32 or ord(value[0]) == 127 or first in ("=", "+", "-", "@"):
        return "'" + value
    return value


def restore_csv_text(value: str) -> str:
    """Decode only a cell explicitly marked by our versioned export metadata."""
    if not value.startswith("'") or escape_csv_text(value[1:]) != value:
        raise ValueError("Invalid CSV escape metadata")
    return value[1:]


# Limit buffered CSV text to roughly 64K characters plus the largest row.
CSV_CHUNK_CHARACTERS = 64 * 1024


def _drain_csv_buffer(output):
    chunk = output.getvalue().encode("utf-8")
    output.seek(0)
    output.truncate(0)
    return chunk


def _iter_csv_chunks(rows, columns, escape_metadata):
    fieldnames = columns + ([CSV_ESCAPE_COLUMN] if escape_metadata else [])
    with io.StringIO(newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL,
                                lineterminator="\n")
        writer.writeheader()
        yield b"\xef\xbb\xbf" + _drain_csv_buffer(output)
        for row in rows:
            safe = {}
            escaped = []
            for key in columns:
                value = row.get(key)
                if isinstance(value, float) and math.isnan(value):
                    value = None
                safe[key] = escape_csv_text(value)
                if isinstance(value, str) and safe[key] != value:
                    escaped.append(key)
            if escape_metadata:
                safe[CSV_ESCAPE_COLUMN] = ",".join(escaped)
            writer.writerow(safe)
            if output.tell() >= CSV_CHUNK_CHARACTERS:
                yield _drain_csv_buffer(output)
        if output.tell():
            yield _drain_csv_buffer(output)


def csv_download(rows, filename: str, columns=None, *, escape_metadata=False, head_only=False):
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    if head_only:
        # Routes have already validated filters and checked for an initial row.
        # No CSV serialization or remaining cursor consumption is needed.
        response = Response(media_type="text/csv", headers=headers)
        del response.headers["content-length"]
        return response
    if columns is None:
        rows = iter(rows)
        first = next(rows)
        columns = list(first.keys())
        rows = chain((first,), rows)
    else:
        columns = list(columns)
    return StreamingResponse(
        _iter_csv_chunks(rows, columns, escape_metadata), media_type="text/csv",
        headers=headers,
    )
