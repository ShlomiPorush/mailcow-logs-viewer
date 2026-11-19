from app.routers.mailbox_stats import format_bytes


def test_whole_bytes_have_no_fraction():
    assert format_bytes(0) == "0 B"
    assert format_bytes(None) == "0 B"
    assert format_bytes(512) == "512 B"


def test_larger_units_keep_one_decimal():
    assert format_bytes(1536) == "1.5 KB"
    assert format_bytes(10 * 1024 * 1024) == "10.0 MB"
