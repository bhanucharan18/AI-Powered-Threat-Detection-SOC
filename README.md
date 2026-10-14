# Security Log Analyzer & Brute-Force Detection System

A local Flask web app that imports authentication logs, validates them, detects suspicious login patterns with
**explainable, rule-based** detection, and lets an analyst investigate alerts, add notes and export reports.

> Educational SOC prototype. It uses **rule-based detection (no machine learning)** on **synthetic sample data**,
> not live enterprise logs. It is not a production SIEM and has **not had a production security audit**.

## Problem statement
Organizations generate large volumes of authentication events. Repeated failures, one IP trying many accounts, or one
account hit from many IPs can be early signs of attempted compromise. Reviewing events by hand is slow. This tool
parses logs, flags patterns with a recorded reason, and links every alert to its evidence. Alerts are *indicators for
investigation*, not proof of an attack.

## Features
- CSV upload with validation (type, size, columns, timestamps, IPs, statuses); malformed rows are rejected and counted
- Three configurable detection rules with evidence-backed alerts; severity and confidence kept separate
- Dashboard (totals, severity chart, hourly activity, top flagged IPs, latest alerts), all computed from SQLite
- Log explorer with server-side pagination and filters; alert list and detail page (timeline, notes, status)
- Reports with date range and CSV export (formula-injection safe)
- CSRF protection, parameterized SQL, escaped output, upload limits, localhost binding

## Architecture
| File | Role |
|---|---|
| `app.py` | Flask routes, CSRF, security headers |
| `log_parser.py` | CSV validation and normalization (UTC) |
| `detector.py` | Pure detection logic (no DB, deterministic) |
| `database.py` | SQLite schema, queries, idempotent alert upsert |
| `report_generator.py` | Safe CSV export |
| `config.py` | Thresholds, limits, investigation guidance |
| `templates/`, `static/` | UI |
| `tests/` | pytest suite |
| `sample_data/` | Synthetic CSV and its generator |

Tables: `events`, `alerts`, `alert_events`, `investigation_notes`, `ingestion_batches`.

## Installation (Windows, VS Code, PowerShell)
```powershell
cd log-analyzer
python -m venv venv
venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. (macOS/Linux: `source venv/bin/activate`.) Optional: set `SECRET_KEY` as an environment
variable; otherwise a random key is generated at each start. Charts load Chart.js from a CDN, so they need internet; tables work offline.

## Using it
1. Dashboard → choose `sample_data/sample_auth_logs.csv` → **Import and analyze**.
2. The import summary shows 162 accepted and 2 rejected rows, plus new alerts.
3. Open **Alerts** → pick one → read *Why it fired*, the evidence timeline, and the steps.
4. Add a note, set status (New / Investigating / Resolved / False Positive).
5. **Reports** → set a date range → download CSVs.

Importing the identical file twice is refused (SHA-256 of the file). Alerts are deduplicated by rule + subject + first-seen time.

## Detection rules (educational defaults, in `config.py`)
| Rule | Default |
|---|---|
| A: failures from one IP | ≥ 5 within 5 min |
| B: failures against one username (any IPs) | ≥ 8 within 10 min |
| C: possible password spraying | one IP failing against ≥ 5 distinct usernames within 10 min |

Windows are inclusive and sliding; overlapping triggers merge into one alert; successes never count as failures.
**Severity:** starts at medium; +1 if peak ≥ 2× threshold; +1 if a success for the same IP/account follows within 10 min.
**Confidence:** low / medium (peak ≥ 1.5×) / high (peak ≥ 2×). These are transparent heuristics that need organizational tuning.

## Tests
```powershell
python -m pytest -q
```
Covers parsing, threshold boundaries (one below / exactly at), window edges, multiple IPs and users, spraying,
duplicate imports and alerts, status/notes, CSRF, filters and export safety. No network required.

## Screenshots
Add your own after running the app (`docs/dashboard.png`, `docs/alert-detail.png`).

## Limitations
- Timestamps assume UTC; shared NAT/proxy IPs, lockouts and stale service credentials cause false positives
- If older events are imported later and move an episode's first-seen time, a second alert can appear
- Detection re-scans all events on each import (fine for thousands of rows, not millions)
- No user login; intended for a single local analyst. No threat-intelligence lookups; no automated response

## Ethical use and data privacy
Use only synthetic or explicitly authorized logs. Sample data uses reserved documentation IP ranges and fictional users.

## Future enhancements
Windows/Linux auth log parsers, more rules, Splunk integration in a test environment, documented threat-intel APIs,
anomaly detection on a suitable dataset. None of these exist yet.
