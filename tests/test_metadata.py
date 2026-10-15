import pytest
from pathlib import Path
from src.metadata import get_file_metadata, format_size


def test_format_size():
    assert format_size(500) == "500.00 B"
    assert format_size(1024) == "1.00 KB"
    assert format_size(1048576) == "1.00 MB"


def test_get_file_metadata(tmp_path):
    p = tmp_path / "metadata_test.txt"
    p.write_text("Hello metadata")

    meta = get_file_metadata(p)
    assert meta["filename"] == "metadata_test.txt"
    assert meta["size_bytes"] == 14
    assert "mime_type" in meta
    assert "created" in meta