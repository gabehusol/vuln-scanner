# VulnScanner

<p align="center">
  <strong>A focused Python CLI for HTTP recon, security header review, exposed path discovery, suspicious content detection, and scan diffing.</strong>
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/Python-3.11%2B-1f6feb">
  <img alt="License MIT" src="https://img.shields.io/badge/License-MIT-15803d">
  <img alt="Interface CLI" src="https://img.shields.io/badge/Interface-CLI-0f766e">
  <img alt="Reports JSON Markdown CSV" src="https://img.shields.io/badge/Reports-JSON%20%7C%20Markdown%20%7C%20CSV-b45309">
</p>

## Overview

VulnScanner is built for a clear workflow. Give it a target, let it inspect headers and likely paths, flag content that looks risky, and save the results in a format you can actually use later.

It is intentionally smaller and easier to understand than a giant security framework. The goal is not to do everything. The goal is to do a focused set of reconnaissance tasks well, present them clearly, and stay maintainable as the project grows.

Currently:

1. A multi command CLI
2. Header analysis for common missing protections
3. Endpoint discovery from wordlists, robots.txt, and sitemap.xml
4. Lightweight technology fingerprinting
5. Content checks for suspicious secrets, debug output, exposed dumps, and archive style files
6. JSON, Markdown, and CSV reporting
7. Saved scan history with report diffing
8. Config driven defaults
9. A test suite for the core logic

## What It Can Do

### Scan Modes

| Command | Purpose |
| --- | --- |
| `scan` | Full workflow with fingerprinting, header checks, path probing, and content analysis |
| `headers` | Header and fingerprint review without path probing |
| `paths` | Endpoint and content checks without header review |
| `history` | Show saved reports |
| `diff` | Compare two saved reports or the latest two runs for a target |

### Detection Coverage

VulnScanner currently looks for:

1. Missing security headers
2. Exposed `Server` and `X-Powered-By` banners
3. Framework and platform clues such as Cloudflare, nginx, Express, FastAPI, Next.js, WordPress, Laravel, Jenkins, Grafana, and more
4. Environment style secrets and token patterns
5. Private key fragments
6. Directory listings
7. phpinfo exposure
8. OpenAPI and Swagger documents
9. SQL dump style content
10. Debug pages and stack traces
11. Directly reachable archive and backup style files

### Reporting And Tracking

Each scan can produce:

1. A console report for quick review
2. A JSON report for automation
3. A Markdown report for sharing or documentation
4. A CSV report for spreadsheet work
5. A timestamped history snapshot under `io/history`
6. A diff view showing what changed between runs

## Workflow

| Stage | What happens |
| --- | --- |
| Input | You provide a target and optional scan settings |
| Recon | VulnScanner fingerprints the target and checks headers |
| Discovery | It probes common paths, robots.txt entries, sitemap paths, and custom wordlists |
| Analysis | It reviews responses for suspicious content and likely technology markers |
| Output | It renders the results to the terminal and optional JSON, Markdown, or CSV reports |
| Tracking | It can save history snapshots and compare runs with `diff` |

## Terminal Preview

```text
VulnScanner
==================================================
Target: https://example.com
Duration: 1.42s
Issues: 4

Fingerprint
==================================================
Final URL: https://example.com
Status: 200
Server: nginx
Content Type: text/html
Technologies: Cloudflare, Next.js, nginx

Header Findings
==================================================
[HIGH] Content-Security-Policy: No content security policy was returned.
[MEDIUM] Strict-Transport-Security: Strict transport security is missing.

Endpoint Findings
==================================================
[403] https://example.com/admin | 1280 bytes | text/html
[200] https://example.com/.well-known/security.txt | 224 bytes | text/plain

Content Findings
==================================================
[MEDIUM] https://example.com/backup.zip | archive-exposure | A backup or archive style file is directly reachable. | backup.zip
```

## Project Layout

```text
VulnScanner/
|  .gitignore
|  LICENSE
|  main.py
|  pyproject.toml
|  README.md
|  vulnscanner.example.json
|
+-- io/
+-- tests/
+-- vulnscanner/
    |  __init__.py
    |  __main__.py
    |  cli.py
    |  config.py
    |  detection.py
    |  diffing.py
    |  http.py
    |  models.py
    |  reporting.py
    |  scanner.py
    |  storage.py
    |  wordlists.py
```

## Installation

### Run It Right Away

```powershell
venv\Scripts\python.exe main.py --help
```

### Run It As A Module

```powershell
venv\Scripts\python.exe -m vulnscanner --help
```

### Install The Console Command

```powershell
venv\Scripts\python.exe -m pip install -e .
```

After that, you can use:

```powershell
vulnscanner --help
```

## Quick Start

### Full Scan

```powershell
vulnscanner scan example.com
```

### Header Review

```powershell
vulnscanner headers example.com
```

### Path And Content Checks

```powershell
vulnscanner paths example.com --max-paths 25
```

### Write All Report Formats

```powershell
vulnscanner scan example.com `
  --json-out io\report.json `
  --markdown-out io\report.md `
  --csv-out io\report.csv
```

### Focus The Scan Scope

```powershell
vulnscanner scan example.com `
  --include "admin*" `
  --include "*.json" `
  --exclude "static/*" `
  --status 200 `
  --status 403 `
  --min-severity medium
```

### Use A Config File

```powershell
vulnscanner --config vulnscanner.example.json scan example.com
```

## Config File Support

VulnScanner reads `vulnscanner.json` automatically when it exists, or you can pass a file explicitly with `--config`.

The merge order is simple:

1. Load `shared`
2. Apply the current command section
3. Let explicit CLI flags override both

Example config:

```json
{
    "shared": {
        "timeout": 5.0,
        "threads": 12,
        "retries": 1,
        "user_agent": "VulnScanner/2.0",
        "json_out": "io/data.json",
        "statuses": [200, 401, 403],
        "max_body_bytes": 250000,
        "verbose": false
    },
    "scan": {
        "max_paths": 25,
        "include_patterns": ["admin*", "*.env", "*.json", "*.zip"],
        "exclude_patterns": ["static/*"],
        "min_severity": "low"
    },
    "paths": {
        "no_content_checks": true
    }
}
```

## History And Diffing

Every saved scan is written under `io/history/<target>/`.

Show scan history:

```powershell
vulnscanner history --target example.com
```

Compare the latest two scans for one target:

```powershell
vulnscanner diff --target example.com
```

Compare any two reports directly:

```powershell
vulnscanner diff io\scan-a.json io\scan-b.json --verbose
```

The diff view highlights:

1. Technology changes
2. New and resolved header findings
3. New and removed endpoints
4. New and resolved content findings
5. Status changes on matching paths

## Testing

Run the current unit suite with:

```powershell
venv\Scripts\python.exe -m unittest discover -s tests -v
```

The test coverage currently focuses on:

1. Config loading and parser defaults
2. Detection behavior
3. Report rendering and exports
4. History storage
5. Diff logic
6. Scope and severity filters

## Responsible Use

Use VulnScanner only against systems you own or are explicitly authorized to assess.

Security tools are most valuable when they are used carefully, documented clearly, and built in a way that others can review and trust.
