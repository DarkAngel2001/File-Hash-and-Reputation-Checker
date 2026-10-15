# File Hash and Reputation Checker

A modular command-line utility written in Python for extracting file metadata, calculating cryptographic hashes (MD5, SHA-1, SHA-256), checking threat intelligence via the official **VirusTotal API**, and generating automated Markdown audit reports.

---

## Features

- **Metadata Extraction:** Gathers file size, MIME type, absolute paths, permissions, and timestamps.
- **Cryptographic Hashing:** Computes MD5, SHA-1, and SHA-256 hashes safely.
- **Threat Intelligence Integration:** Queries the VirusTotal v3 API with built-in response caching to respect rate limits.
- **Safety-by-Design:** Defaults to safe **hash-only lookups**. File uploads require an explicit `--upload` flag to prevent accidental submissions.
- **Automated Reporting:** Outputs clean, timestamped Markdown audit reports into a `reports/` directory.

---

## Project Structure

```text
file-reputation-checker/
│
├── .env.example            # Template for environment variables
├── requirements.txt        # Project dependencies
├── README.md               # Project documentation
│
├── src/                    # Core source code package
│   ├── __init__.py
│   ├── cli.py              # Command-line interface & report generator
│   ├── hashing.py          # Cryptographic hashing module
│   ├── metadata.py         # File metadata extractor
│   └── reputation.py       # VirusTotal API & local caching logic
│
├── tests/                  # Pytest test suite
│   ├── __init__.py
│   ├── test_cli.py
│   ├── test_hashing.py
│   ├── test_metadata.py
│   └── test_reputation.py
│
├── test_files/             # Sample files for testing & scanning
│   ├── sample.txt
│   ├── sample.json
│   └── sample.bin
│
└── reports/                # Automatically generated markdown reports
```

---

## Installation & Setup

### 1. Set Up Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

### 2. Install Dependencies
Install the required packages listed in `requirements.txt`:
```powershell
pip install -r requirements.txt
```

### 3. Configure Environment Variables
1. Copy `.env.example` and rename it to `.env`:
   ```powershell
   copy .env.example .env
   ```
2. Open `.env` and add your official VirusTotal API key:
   ```env
   VT_API_KEY=your_actual_virustotal_api_key_here
   ```

---

## Running the Test Suite

This project uses `pytest` for unit testing and mocking API responses. To run all tests with verbose output, execute:

```powershell
python -m pytest -v
```

---

## Usage & Examples

The tool is executed using Python's module runner (`-m`) from the project root.

### 1. Scan a Text File (Hash-Only Lookup)
Checks file metadata, computes hashes, and queries VirusTotal safely via its hash without uploading the file content:
```powershell
python -m src.cli test_files/sample.txt
```

### 2. Scan a JSON File
```powershell
python -m src.cli test_files/sample.json
```

### 3. Test Local Caching
Run the same file scan a second time to observe instant retrieval from the local cache (`.cache/lookup_cache.json`) without burning API rate limits:
```powershell
python -m src.cli test_files/sample.txt
```

### 4. Scan a Binary File with Explicit Upload (`--upload`)
To comply with safety protocols, uploading a file to VirusTotal requires the explicit `--upload` flag:
```powershell
python -m src.cli test_files/sample.bin --upload
```

---

## Generated Reports

After running any scan command, a timestamped audit report will be generated and saved inside the `reports/` folder (e.g., `reports/report_sample.txt_20261014_120000.md`). Each report includes:
- File Metadata & Permissions Table
- Cryptographic Hashes (MD5, SHA-1, SHA-256)
- VirusTotal Reputation Analysis Summary
- File Upload Results (if `--upload` was specified)