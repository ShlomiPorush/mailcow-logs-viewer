"""Verify incremental output and byte-compatible Unicode CSV across chunks."""
import asyncio
import csv
import io
from app.services.csv_export import csv_download


def test_csv_produces_header_before_consuming_rows_and_stops_early():
    consumed = []
    def rows():
        for number in range(10000):
            consumed.append(number)
            yield {"text": "x" * 1024}
    response = csv_download(rows(), "test.csv", columns=["text"])
    assert consumed == []
    async def run():
        header = await anext(response.body_iterator)
        assert header == b'\xef\xbb\xbf"text"\n'
        assert consumed == []
        chunk = await anext(response.body_iterator)
        assert chunk
        assert 0 < len(consumed) < 10000
        count = len(consumed)
        await response.body_iterator.aclose()
        assert len(consumed) == count
    asyncio.run(run())


def test_chunk_boundaries_preserve_unicode_quotes_and_newlines():
    text = '\u05e9\u05dc\u05d5\u05dd, "quoted"\n\u4f60\u597d \U0001f600' * 200
    rows = [{"text": text, "score": -1.5} for _ in range(100)]
    expected = io.StringIO(newline="")
    writer = csv.DictWriter(expected, fieldnames=["text", "score"], quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    response = csv_download(rows, "test.csv")
    async def run():
        chunks = [chunk async for chunk in response.body_iterator]
        assert b"".join(chunks) == expected.getvalue().encode("utf-8-sig")
        assert sum(chunk.startswith(b"\xef\xbb\xbf") for chunk in chunks) == 1
    asyncio.run(run())
