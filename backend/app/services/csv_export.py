"""Spreadsheet-oriented CSV serialization shared by every download endpoint."""
import csv
import io
import math
import unicodedata
from fastapi.responses import StreamingResponse

# Suppression exports carry the exact escaped field names for lossless re-import.
CSV_ESCAPE_COLUMN = "_csv_escape_v1"


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


def csv_download(rows, filename: str, columns=None, *, escape_metadata=False):
    columns = list(columns if columns is not None else rows[0].keys())
    fieldnames = columns + ([CSV_ESCAPE_COLUMN] if escape_metadata else [])
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL,
                            lineterminator="\n")
    writer.writeheader()
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
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
