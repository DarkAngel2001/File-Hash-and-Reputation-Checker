import json
import os
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=True,
)

CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_FILE = CACHE_DIR / "lookup_cache.json"

VT_FILES_URL = "https://www.virustotal.com/api/v3/files"
PLACEHOLDER_API_KEY = "your_virustotal_api_key_here"


def _get_api_key(api_key: Optional[str] = None) -> Optional[str]:
    """
    Get and normalize the VirusTotal API key.

    A key passed directly to the function takes precedence over .env.
    """
    value = api_key

    if value is None:
        value = os.getenv("VT_API_KEY")

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    if value == PLACEHOLDER_API_KEY:
        return None

    return value


def _load_cache() -> dict:
    """Load the local lookup cache."""
    if not CACHE_FILE.exists():
        return {}

    try:
        with CACHE_FILE.open("r", encoding="utf-8") as file:
            cache = json.load(file)

        return cache if isinstance(cache, dict) else {}

    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache_data: dict) -> None:
    """Save lookup results to the local cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    temporary_file = CACHE_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(cache_data, file, indent=2)

    temporary_file.replace(CACHE_FILE)


def _cached_result(cached_value: dict) -> dict:
    """
    Convert a cached value into the public reputation result format.

    New cache entries use an internal '_status' marker for not_found results.
    Older cache entries containing VirusTotal data are treated as successful
    cached results.
    """
    if (
        isinstance(cached_value, dict)
        and cached_value.get("_status") == "not_found"
    ):
        return {
            "status": "cached",
            "message": cached_value.get(
                "_message",
                "Hash not found in VirusTotal database.",
            ),
        }

    return {
        "status": "cached",
        "data": cached_value,
    }


def check_reputation(
    sha256: str,
    api_key: Optional[str] = None,
) -> dict:
    """
    Query VirusTotal by SHA-256.

    This function sends only the hash. It never uploads the file.
    """
    api_key = _get_api_key(api_key)

    if not api_key:
        return {
            "status": "skipped",
            "message": "No API key provided.",
        }

    cache = _load_cache()

    if sha256 in cache:
        return _cached_result(cache[sha256])

    url = f"{VT_FILES_URL}/{sha256}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
        )

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": f"Network error: {error}",
        }

    if response.status_code == 200:
        try:
            result = response.json()

        except ValueError:
            return {
                "status": "error",
                "message": "VirusTotal returned invalid JSON.",
            }

        cache[sha256] = result

        try:
            _save_cache(cache)

        except OSError as error:
            return {
                "status": "success",
                "data": result,
                "cache_warning": f"Could not save cache: {error}",
            }

        return {
            "status": "success",
            "data": result,
        }

    if response.status_code == 404:
        not_found_message = "Hash not found in VirusTotal database."

        cache[sha256] = {
            "_status": "not_found",
            "_message": not_found_message,
        }

        try:
            _save_cache(cache)

        except OSError:
            pass

        return {
            "status": "not_found",
            "message": not_found_message,
        }

    if response.status_code == 401:
        return {
            "status": "error",
            "message": (
                "VirusTotal rejected the API key. "
                "Check the personal API key in the project .env file."
            ),
        }

    return {
        "status": "error",
        "message": (
            f"API error code {response.status_code}: "
            f"{response.text}"
        ),
    }


def upload_file_to_vt(file_path, api_key=None):
    # Fallback to .env if no explicit api_key is passed via CLI
    if not api_key:
        api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "status": "skipped",
            "message": "VirusTotal API key not found. Set VT_API_KEY in .env or pass --api-key."
        }

    url = "https://www.virustotal.com/api/v3/files"
    # VirusTotal strictly expects lowercase 'x-apikey'
    headers = {
        "x-apikey": api_key
    }

    try:
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f)}
            response = requests.post(url, headers=headers, files=files, timeout=30)

        if response.status_code == 200:
            return {
                "status": "success",
                "data": response.json()
            }
        else:
            return {
                "status": "error",
                "message": f"API Error {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }