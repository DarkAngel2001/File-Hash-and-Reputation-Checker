import pytest
from pathlib import Path
from src.hashing import calculate_hashes


def test_calculate_hashes(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "hello.txt"
    p.write_bytes(b"test content")

    hashes = calculate_hashes(p)

    # Correct hashes for raw bytes b"test content"
    assert hashes["md5"] == "9473fdd0d880a43c21b7778d34872157"
    assert hashes["sha1"] == "1eebdf4fdc9fc7bf283031b93f9aef3338de9052"
    assert hashes["sha256"] == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"