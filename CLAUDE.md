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
- `app/ingestion/matrix_parser.py`   — parses Excel policy matrix → PolicyRule objects; supports IT/OT grid format and columnar format
- `app/ingestion/rulebase_parser.py` — parses Palo Alto CSV rulebase → FirewallRule objects
- `app/ingestion/normalizer.py`      — aligns both models to common schema; translates raw FW zone names → ATPSG zones via zone_map
- `app/models/__init__.py`           — PolicyRule, FirewallRule, Finding dataclasses
- `app/validation/checks.py`         — 4 check functions (unauthorized, condition, missing, hygiene)
- `app/validation/engine.py`         — orchestrates checks, scores, returns AuditResult
- `app/reporting/excel_report.py`    — color-coded Excel report; generate_excel_report(AuditResult) → bytes
- `app/reporting/pdf_report.py`      — A4 PDF report; generate_pdf_report(AuditResult) → bytes
- `app/routes.py`                    — GET / · POST /upload · GET /download/<job_id>/excel · GET /download/<job_id>/pdf
- `app/templates/index.html`         — upload UI; posts to /upload, renders findings table
- `app/static/ntt_data_logo.png`     — NTT DATA company logo served by Flask static handler; displayed in header
- `tests/test_checks.py`             — 42 pytest unit tests for all 4 validation checks
- `.gitignore`                       — excludes __pycache__, bytecode, venvs, editor artifacts

## Data Models
- PolicyRule: what the MATRIX says is allowed/denied (source_zone, dest_zone, ports, profiles, action, deny_severity)
  - `deny_severity` is set for deny-action rules only: `"HIGH"` for "Should not be allowed", `"CRITICAL"` for "Shall not be allowed"
- FirewallRule: what the FIREWALL actually has (rule_name, zones, services, profiles, logging)
  - Rules with `action="deny"` are discarded before auditing — only allow rules are validated
- Finding: a compliance violation (type, severity, description, remediation)

## Validation Checks

Firewall rules with `action="deny"` are discarded before all checks — only `allow` rules are audited.

1. UNAUTHORIZED_FLOW    — firewall allow rule with no matching matrix entry (CRITICAL)
2. CONDITION_VIOLATION  — wrong ports / missing profiles / no logging (HIGH/MEDIUM);
   action mismatch severity follows the matrix: "Should not be allowed" → HIGH, "Shall not be allowed" → CRITICAL
3. MISSING_IMPLEMENTATION — allow matrix entry with no firewall rule (MEDIUM)
4. HYGIENE              — disabled rules, any-zone permit, shadowed rules (LOW/CRITICAL);
   "any" in source OR destination zone → CRITICAL ("Shall not be allowed"); description names the offending zone(s)

## Dev Setup
```bash
pip install -r requirements.txt
python run.py
# Open http://localhost:5000/ in a browser to use the upload UI
# Or POST directly to http://localhost:5000/upload with matrix + rulebase files

# Run unit tests
pytest tests/test_checks.py -v
```

## Matrix Parser — Supported Formats

`parse_matrix(filepath) -> List[PolicyRule]`

### Format 1 — IT/OT Grid (auto-detected, preferred)
Zone names appear as both row headers (source) and column headers (destination).
Cell text determines the policy:

| Cell text | Action | `deny_severity` |
|---|---|---|
| "May be allowed" | `allow` | — |
| "Within a shop may be allowed…" | `allow` | — |
| "Should not be allowed²" | `deny` | `HIGH` (conditional prohibition; footnote markers stripped) |
| "Shall not be allowed" | `deny` | `CRITICAL` (absolute prohibition) |
| "Direct access shall not be allowed…" | `deny` | `CRITICAL` |
| "Out of scope" / blank / diagonal | skipped | — |

`deny_severity` controls the severity of a CONDITION_VIOLATION finding when a firewall `allow` rule contradicts a matrix `deny` entry.

- Scans first sheet whose name contains "matrix" first, then all other sheets
- Header row auto-detected by finding a row with ≥ 3 known zone names
- Zone names normalised via `ZONE_ALIASES`: "OT-DMZ" == "OT DMZ" == "ot dmz"
- All parsed rules default to `allowed_ports={"any"}`, `logging_required=True`

### Format 2 — Columnar (fallback)
Explicit columns: `Source Zone`, `Destination Zone`, `Action`, plus optional
`Allowed Ports`, `Allowed Applications`, `AV Profile`, `URL Profile`, `Log Required`.

### Zone Assignments sheet
`load_zone_assignments(filepath)` reads the optional "Zone Assignments" sheet
and returns a `dict[raw_zone_name → canonical_atpsg_zone]`.

Expected sheet columns (case-insensitive):

| Column | Contains |
|---|---|
| `Zone` | Raw firewall zone name (e.g. `outside`, `ot-dmz-sr`) |
| `ATPSG Zone` | Canonical ATPSG zone name (e.g. `IT Zone`, `OT DMZ`) |

- The ATPSG column is detected by looking for `"atpsg"` in the header name.
- Rows where the ATPSG Zone cell is `?` (unmapped) are skipped.
- Fallback: if no `"atpsg"` header is found, col[0]=raw, col[1]=canonical.
- All keys stored lower-case; values passed through `_canonical_zone()`.

This mapping is applied by `normalize_firewall_rules()` so that raw firewall
zone names (e.g. `outside`, `ot-dmz-sr`) are translated to canonical ATPSG
zone names (e.g. `it zone`, `ot dmz`) before comparison with the policy matrix.
Zones not present in the map are kept as-is (pass-through).

## Next Components to Build
- [x] app/reporting/excel_report.py   — color-coded Excel output (done 2026-03-05)
- [x] app/reporting/pdf_report.py     — A4 PDF report with summary + findings (done 2026-03-06)
- [x] templates/index.html            — upload UI (done 2026-03-05)
- [x] tests/test_checks.py            — 37 unit tests for all 4 checks (done 2026-03-05)
- [x] load_zone_assignments column detection bug (fixed 2026-03-10)
- [x] NTT DATA logo in UI header (done 2026-03-10)
- [ ] GET /results/<job_id>           — retrieve stored results
- [x] GET /download/<job_id>/excel    — stream saved .xlsx report (done 2026-03-05)
- [x] GET /download/<job_id>/pdf      — stream saved .pdf report (done 2026-03-06)

## Reporting — Excel
`generate_excel_report(result: AuditResult) -> bytes` (openpyxl)

- **Summary sheet**: compliance score with green/yellow/red fill, rating, rule counts,
  findings breakdown by severity and type, full audit summary text
- **Findings sheet**: one row per Finding, frozen header, sorted CRITICAL→HIGH→MEDIUM→LOW;
  severity column filled red/orange/yellow/green; all columns tinted per severity for scannability
- Zero-findings case renders a "fully compliant" placeholder row
- Returns raw `.xlsx` bytes — write to disk or stream as HTTP response

## Reporting — PDF
`generate_pdf_report(result: AuditResult) -> bytes` (reportlab)

- **Page 1 — Executive Summary**: colour-coded compliance score box (green/yellow/red),
  rating label, rule counts, findings by severity table, findings by type table, summary text
- **Page 2+ — Findings Detail**: one row per Finding sorted CRITICAL→LOW; severity cell
  solid-filled, all other columns tinted by severity; wrapping text in description/remediation
- Returns raw `.pdf` bytes

## Routes
- `GET /`                        — serves upload UI
- `POST /upload`                 — runs full audit pipeline; saves `report.xlsx` and
  `report.pdf` to `reports/<job_id>/`; returns JSON with findings + `download_excel`/`download_pdf` URLs
- `GET /download/<job_id>/excel` — streams the saved `.xlsx` report as an attachment
- `GET /download/<job_id>/pdf`   — streams the saved `.pdf` report as an attachment

## UI — templates/index.html
Single-page upload interface served by `GET /`.

- Two drag-and-drop file inputs: matrix (.xlsx) and rulebase (.csv)
- Submits via `fetch` to `POST /upload` (multipart/form-data); no page reload
- **Score circle**: green (≥90) / yellow (70–89) / red (<70) with COMPLIANT / PARTIALLY COMPLIANT / NON-COMPLIANT label
- **Severity chips**: live counts for CRITICAL / HIGH / MEDIUM / LOW
- **Findings table**: rows tinted by severity, severity badge color-coded red/orange/yellow/green,
  filter buttons to narrow by severity, XSS-safe rendering
- Zero-findings state renders a "fully compliant" message
- **Download bar**: appears after a successful audit with Excel (.xlsx) and PDF buttons
  linking to `GET /download/<job_id>/excel` and `/pdf`
- **Header logo**: NTT DATA logo (`app/static/ntt_data_logo.png`) displayed on a white
  pill background in the page header, left of the title; served via `url_for('static', ...)`
- `GET /` added to `app/routes.py` to serve the template
- Template lives at `app/templates/index.html` (Flask resolves templates relative to the `app/` package root)
- Static assets live at `app/static/`; Flask serves them at `/static/<filename>`
- `static_folder` is set to an explicit absolute path in `create_app()` (`Path(__file__).resolve().parent / "static"`) to prevent 404s from WSL/Windows path resolution quirks

## Tests — tests/test_checks.py
42 pytest unit tests covering all four check functions (42/42 passing).

| Class | Tests | What's covered |
|---|---|---|
| `TestCheckUnauthorizedFlows` | 8 | zone match, no-match (CRITICAL), disabled/deny skip, any-wildcard, multi-rule isolation, empty inputs |
| `TestCheckConditionViolations` | 15 | compliant baseline, port violation (HIGH), `any`/`app-default` exemptions, missing logging (MEDIUM), log-forwarding as alternative, missing AV/URL profiles (HIGH), profile-group bypass, action mismatch (CRITICAL), "shall not be allowed" → CRITICAL, "should not be allowed" → HIGH, deny FW rule skipped, disabled/unmatched rule skip |
| `TestCheckMissingImplementations` | 7 | covered flow, uncovered flow (MEDIUM), disabled-rule gap, deny-policy skip, any-zone coverage, multi-policy isolation, empty inputs |
| `TestCheckHygiene` | 11 | clean rule baseline, disabled (LOW), any-any permit (CRITICAL), any-any deny skip, any-source-zone (CRITICAL), any-dest-zone (CRITICAL), shadowed rule (LOW), reversed-order no-shadow, partial-overlap no-shadow, disabled broad rule not shadowing, only first shadower reported |

Fixtures `make_policy()` and `make_fw_rule()` provide sensible defaults for minimal test setup.
