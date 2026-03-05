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
- `app/routes.py`                    — GET / (index) + POST /upload endpoint
- `templates/index.html`             — upload UI; posts to /upload, renders findings table
- `tests/test_checks.py`             — 37 pytest unit tests for all 4 validation checks
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
# Open http://localhost:5000/ in a browser to use the upload UI
# Or POST directly to http://localhost:5000/upload with matrix + rulebase files

# Run unit tests
pytest tests/test_checks.py -v
```

## Next Components to Build
- [x] app/reporting/excel_report.py   — color-coded Excel output (done 2026-03-05)
- [ ] app/reporting/pdf_report.py     — PDF summary report
- [x] templates/index.html            — upload UI (done 2026-03-05)
- [x] tests/test_checks.py            — 37 unit tests for all 4 checks (done 2026-03-05)
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

## UI — templates/index.html
Single-page upload interface served by `GET /`.

- Two drag-and-drop file inputs: matrix (.xlsx) and rulebase (.csv)
- Submits via `fetch` to `POST /upload` (multipart/form-data); no page reload
- **Score circle**: green (≥90) / yellow (70–89) / red (<70) with COMPLIANT / PARTIALLY COMPLIANT / NON-COMPLIANT label
- **Severity chips**: live counts for CRITICAL / HIGH / MEDIUM / LOW
- **Findings table**: rows tinted by severity, severity badge color-coded red/orange/yellow/green,
  filter buttons to narrow by severity, XSS-safe rendering
- Zero-findings state renders a "fully compliant" message
- `GET /` added to `app/routes.py` to serve the template

## Tests — tests/test_checks.py
37 pytest unit tests covering all four check functions (37/37 passing).

| Class | Tests | What's covered |
|---|---|---|
| `TestCheckUnauthorizedFlows` | 8 | zone match, no-match (CRITICAL), disabled/deny skip, any-wildcard, multi-rule isolation, empty inputs |
| `TestCheckConditionViolations` | 11 | compliant baseline, port violation (HIGH), `any`/`app-default` exemptions, missing logging (MEDIUM), log-forwarding as alternative, missing AV/URL profiles (HIGH), profile-group bypass, action mismatch (CRITICAL), disabled/unmatched rule skip |
| `TestCheckMissingImplementations` | 7 | covered flow, uncovered flow (MEDIUM), disabled-rule gap, deny-policy skip, any-zone coverage, multi-policy isolation, empty inputs |
| `TestCheckHygiene` | 9 | clean rule baseline, disabled (LOW), any-any permit (CRITICAL), any-any deny skip, shadowed rule (LOW), reversed-order no-shadow, partial-overlap no-shadow, disabled broad rule not shadowing, only first shadower reported |

Fixtures `make_policy()` and `make_fw_rule()` provide sensible defaults for minimal test setup.
