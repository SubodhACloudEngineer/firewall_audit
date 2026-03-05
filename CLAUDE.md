# Firewall Compliance Audit Engine

## Project Purpose
Flask-based web portal that accepts a Security Policy Matrix (Excel) and a
Palo Alto firewall rulebase (CSV export), validates the rulebase against the
matrix, and generates a compliance report.

## Architecture
```
Upload (xlsx + csv)
  → Ingestion Layer (parse + normalize)
  → Validation Engine (4 checks)
  → Scoring
  → Report (Excel + PDF)
```

## Key Files
- `app/ingestion/matrix_parser.py`   — parses Excel policy matrix → PolicyRule objects
- `app/ingestion/rulebase_parser.py` — parses Palo Alto CSV rulebase → FirewallRule objects
- `app/ingestion/normalizer.py`      — aligns both models to common schema
- `app/models/__init__.py`           — PolicyRule, FirewallRule, Finding dataclasses
- `app/validation/checks.py`         — 4 check functions (unauthorized, condition, missing, hygiene)
- `app/validation/engine.py`         — orchestrates checks, scores, returns AuditResult
- `app/reporting/excel_report.py`    — color-coded Excel report; generate_excel_report(AuditResult) → bytes
- `app/routes.py`                    — POST /upload endpoint
- `.gitignore`                       — excludes __pycache__, bytecode, venvs, editor artifacts

## Data Models
- PolicyRule: what the MATRIX says is allowed (source_zone, dest_zone, ports, profiles, action)
- FirewallRule: what the FIREWALL actually has (rule_name, zones, services, profiles, logging)
- Finding: a compliance violation (type, severity, description, remediation)

## Validation Checks
1. UNAUTHORIZED_FLOW    — firewall rule with no matching matrix entry (CRITICAL)
2. CONDITION_VIOLATION  — wrong ports / missing profiles / no logging (HIGH/MEDIUM)
3. MISSING_IMPLEMENTATION — matrix entry with no firewall rule (MEDIUM)
4. HYGIENE              — disabled rules, any-any, shadowed rules (LOW/CRITICAL)

## Dev Setup
```bash
pip install -r requirements.txt
python run.py
# POST to http://localhost:5000/upload with matrix + rulebase files
```

## Next Components to Build
- [x] app/reporting/excel_report.py   — color-coded Excel output (done 2026-03-05)
- [ ] app/reporting/pdf_report.py     — PDF summary report
- [ ] templates/index.html            — upload UI
- [ ] tests/test_checks.py            — unit tests for validation checks
- [ ] GET /results/<job_id>           — retrieve stored results
- [ ] GET /download/<job_id>          — download generated report

## Reporting — Excel
`generate_excel_report(result: AuditResult) -> bytes` (openpyxl)

- **Summary sheet**: compliance score with green/yellow/red fill, rating, rule counts,
  findings breakdown by severity and type, full audit summary text
- **Findings sheet**: one row per Finding, frozen header, sorted CRITICAL→HIGH→MEDIUM→LOW;
  severity column filled red/orange/yellow/green; all columns tinted per severity for scannability
- Zero-findings case renders a "fully compliant" placeholder row
- Returns raw `.xlsx` bytes — write to disk or stream as HTTP response
