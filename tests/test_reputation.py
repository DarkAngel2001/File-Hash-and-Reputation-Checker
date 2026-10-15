from unittest.mock import Mock, patch

from src.reputation import check_reputation


@patch("src.reputation._load_cache", return_value={})
@patch("src.reputation._save_cache")
@patch("src.reputation.requests.get")
def test_check_reputation_success(
    mock_get,
    mock_save_cache,
    mock_load_cache,
):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 65,
                    "undetected": 0,
                }
            }
        }
    }

    mock_get.return_value = mock_response

    result = check_reputation(
        "dummy_sha256_hash",
        api_key="fake_key",
    )

    assert result["status"] == "success"

    stats = result["data"]["data"]["attributes"]["last_analysis_stats"]

    assert stats["harmless"] == 65
    assert stats["malicious"] == 0

    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/files/dummy_sha256_hash",
        headers={
            "x-apikey": "fake_key",
            "accept": "application/json",
        },
        timeout=10,
    )

    mock_save_cache.assert_called_once()


@patch("src.reputation._load_cache", return_value={})
@patch("src.reputation.requests.get")
def test_check_reputation_not_found(
    mock_get,
    mock_load_cache,
):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    result = check_reputation(
        "unknown_hash",
        api_key="fake_key",
    )

    assert result["status"] == "not_found"
    assert "not found" in result["message"].lower()

    mock_get.assert_called_once()


def test_check_reputation_no_key(monkeypatch):
    """
    This test must not use the developer's real .env API key.
    """
    monkeypatch.delenv("VT_API_KEY", raising=False)

    with patch("src.reputation.os.getenv", return_value=None):
        result = check_reputation(
            "dummy_sha256_hash",
            api_key=None,
        )

    assert result["status"] == "skipped"
    assert result["message"] == "No API key provided."


@patch(
    "src.reputation._load_cache",
    return_value={
        "existing_hash": {
            "cached": True,
        }
    },
)
@patch("src.reputation.requests.get")
def test_check_reputation_cached(
    mock_get,
    mock_load_cache,
):
    result = check_reputation(
        "existing_hash",
        api_key="fake_key",
    )

    assert result["status"] == "cached"
    assert result["data"]["cached"] is True

    # A cached result must not make an API request.
    mock_get.assert_not_called()


@patch("src.reputation._load_cache", return_value={})
@patch("src.reputation.requests.get")
def test_check_reputation_invalid_api_key(
    mock_get,
    mock_load_cache,
):
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.text = (
        '{"error": {"code": "WrongCredentialsError", '
        '"message": "Wrong API key"}}'
    )

    mock_get.return_value = mock_response

    result = check_reputation(
        "dummy_sha256_hash",
        api_key="invalid_key",
    )

    assert result["status"] == "error"
    assert "rejected the API key" in result["message"]


@patch("src.reputation._load_cache", return_value={})
@patch("src.reputation.requests.get")
def test_check_reputation_network_error(
    mock_get,
    mock_load_cache,
):
    import requests

    mock_get.side_effect = requests.RequestException(
        "connection failed"
    )

    result = check_reputation(
        "dummy_sha256_hash",
        api_key="fake_key",
    )

    assert result["status"] == "error"
    assert "Network error" in result["message"]