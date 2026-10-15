from pathlib import Path
from unittest.mock import patch

from src.cli import generate_markdown_report, main


def test_cli_creates_report(tmp_path, monkeypatch):
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("safe test content", encoding="utf-8")

    reports_dir = tmp_path / "reports"
    monkeypatch.chdir(tmp_path)

    with patch(
        "src.cli.check_reputation",
        return_value={
            "status": "skipped",
            "message": "No API key provided.",
        },
    ):
        monkeypatch.setattr(
            "sys.argv",
            [
                "scanner.py",
                str(sample_file),
            ],
        )

        main()

    reports = list(reports_dir.glob("*.md"))

    assert len(reports) == 1

    report_content = reports[0].read_text(encoding="utf-8")

    assert "# File Analysis Report" in report_content
    assert "sample.txt" in report_content
    assert "MD5" in report_content
    assert "SHA-1" in report_content
    assert "SHA-256" in report_content
    assert "No API key provided." in report_content


def test_cli_uses_explicit_api_key(tmp_path, monkeypatch):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"binary test content")

    monkeypatch.chdir(tmp_path)

    reputation_result = {
        "status": "not_found",
        "message": "Hash not found in VirusTotal database.",
    }

    with patch(
        "src.cli.check_reputation",
        return_value=reputation_result,
    ) as mock_check_reputation:
        monkeypatch.setattr(
            "sys.argv",
            [
                "scanner.py",
                str(sample_file),
                "--api-key",
                "test_api_key",
            ],
        )

        main()

    mock_check_reputation.assert_called_once()
    assert mock_check_reputation.call_args.kwargs["api_key"] == "test_api_key"

    reports = list((tmp_path / "reports").glob("*.md"))
    assert len(reports) == 1

    report_content = reports[0].read_text(encoding="utf-8")
    assert "not_found" in report_content
    assert "Hash not found in VirusTotal database." in report_content


def test_cli_upload_requires_explicit_flag(tmp_path, monkeypatch):
    sample_file = tmp_path / "sample.json"
    sample_file.write_text('{"test": true}', encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    reputation_result = {
        "status": "skipped",
        "message": "No API key provided.",
    }

    with patch(
        "src.cli.check_reputation",
        return_value=reputation_result,
    ), patch("src.cli.upload_file_to_vt") as mock_upload:
        monkeypatch.setattr(
            "sys.argv",
            [
                "scanner.py",
                str(sample_file),
            ],
        )

        main()

    mock_upload.assert_not_called()


def test_cli_upload_runs_with_explicit_flag(tmp_path, monkeypatch):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"upload test content")

    monkeypatch.chdir(tmp_path)

    reputation_result = {
        "status": "skipped",
        "message": "No API key provided.",
    }

    upload_result = {
        "status": "success",
        "data": {
            "type": "analysis",
            "id": "test-analysis-id",
        },
    }

    with patch(
        "src.cli.check_reputation",
        return_value=reputation_result,
    ), patch(
        "src.cli.upload_file_to_vt",
        return_value=upload_result,
    ) as mock_upload:
        monkeypatch.setattr(
            "sys.argv",
            [
                "scanner.py",
                str(sample_file),
                "--upload",
                "--api-key",
                "test_api_key",
            ],
        )

        main()

    mock_upload.assert_called_once_with(
        sample_file,
        api_key="test_api_key",
    )

    reports = list((tmp_path / "reports").glob("*.md"))
    assert len(reports) == 1

    report_content = reports[0].read_text(encoding="utf-8")
    assert "File Upload Result" in report_content
    assert "test-analysis-id" in report_content


def test_generate_markdown_report_displays_cached_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    metadata = {
        "filename": "example.txt",
        "absolute_path": str(tmp_path / "example.txt"),
        "size_bytes": 10,
        "size_human": "10.00 B",
        "mime_type": "text/plain",
        "created": "2026-01-01T00:00:00",
        "modified": "2026-01-01T00:00:00",
        "accessed": "2026-01-01T00:00:00",
        "permissions": "644",
    }

    hashes = {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    }

    reputation = {
        "status": "cached",
        "message": "Hash not found in VirusTotal database.",
    }

    report_path = generate_markdown_report(
        metadata,
        hashes,
        reputation,
    )

    assert report_path.exists()

    report_content = report_path.read_text(encoding="utf-8")

    assert "Status:** `cached`" in report_content
    assert "Hash not found in VirusTotal database." in report_content
