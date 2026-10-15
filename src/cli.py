import argparse
import sys
from pathlib import Path
from datetime import datetime

from src.hashing import calculate_hashes
from src.metadata import get_file_metadata
from src.reputation import check_reputation, upload_file_to_vt


def generate_markdown_report(metadata: dict, hashes: dict, reputation: dict, upload_result: dict = None) -> Path:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = reports_dir / f"report_{metadata['filename']}_{timestamp}.md"

    status = reputation.get("status")
    stats_str = "N/A"
    
    if status in ["success", "cached"]:
        data = reputation.get("data", {})
        if "attributes" in data:
            attributes = data.get("attributes", {})
        elif "data" in data and "attributes" in data.get("data", {}):
            attributes = data.get("data", {}).get("attributes", {})
        else:
            attributes = {}

        stats = attributes.get("last_analysis_stats", {})
        if stats:
            stats_str = f"Malicious: {stats.get('malicious', 0)} | Suspicious: {stats.get('suspicious', 0)} | Harmless: {stats.get('harmless', 0)} | Undetected: {stats.get('undetected', 0)}"
        else:
            stats_str = reputation.get("message", "Cached result found.")
    elif status == "not_found":
        stats_str = "Hash not found in VirusTotal database."
    else:
        stats_str = reputation.get("message", "Not queried or error.")

    content = f"""# File Analysis Report

- **Generated At:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Target File:** `{metadata['filename']}`

## 1. File Metadata
| Property | Value |
| :--- | :--- |
| **Absolute Path** | `{metadata['absolute_path']}` |
| **File Size** | {metadata['size_human']} ({metadata['size_bytes']} bytes) |
| **MIME Type** | `{metadata['mime_type']}` |
| **Created Time** | {metadata['created']} |
| **Modified Time** | {metadata['modified']} |
| **Permissions** | `{metadata['permissions']}` |

## 2. Cryptographic Hashes
| Algorithm | Hash Value |
| :--- | :--- |
| **MD5** | `{hashes['md5']}` |
| **SHA-1** | `{hashes['sha1']}` |
| **SHA-256** | `{hashes['sha256']}` |

## 3. Reputation Check
- **Status:** `{status}`
- **Analysis Summary:** {stats_str}
"""

    if upload_result:
        content += f"""
## 4. File Upload Result
- **Status:** `{upload_result.get('status')}`
- **Details:** `{upload_result}`
"""

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(content)

    return report_filename


def main():
    parser = argparse.ArgumentParser(description="File Hash and Reputation Checker Tool")
    parser.add_argument("file", type=str, help="Path to the file to analyze")
    parser.add_argument("--upload", action="store_true", help="Explicitly upload the file to the reputation service")
    parser.add_argument("--api-key", type=str, help="Provide API key directly via CLI", default=None)

    args = parser.parse_args()
    file_path = Path(args.file)

    if not file_path.exists() or not file_path.is_file():
        print(f"[Error] File not found or is not a valid file: {file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing file: {file_path.name}...")

    metadata = get_file_metadata(file_path)
    hashes = calculate_hashes(file_path)
    reputation = check_reputation(hashes["sha256"], api_key=args.api_key)

    upload_result = None
    if args.upload:
        print("[!] Explicit upload flag detected. Uploading file...")
        upload_result = upload_file_to_vt(file_path, api_key=args.api_key)

    report_path = generate_markdown_report(metadata, hashes, reputation, upload_result)
    print(f"\n[+] Analysis complete! Report saved to: {report_path}")


if __name__ == "__main__":
    main()