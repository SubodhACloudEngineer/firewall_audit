"""
Matrix Parser
Reads the Security Policy Matrix from an Excel (.xlsx) file and converts
it into PolicyRule objects.

Supports two formats:
  1. Grid format (IT/OT matrix): zone names appear as both row and column
     headers; cells contain natural-language text such as:
       "May be allowed", "Shall not be allowed", "Should not be allowed²"
  2. Columnar format (legacy): each row has explicit Source Zone /
     Destination Zone / Action / … columns.

The optional 'Zone Assignments' sheet is also parsed (if present) to build
a mapping from interface/VLAN names to canonical zone names.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from app.models import PolicyRule

logger = logging.getLogger(__name__)


# ─── Zone name normalization ──────────────────────────────────────────────────

# Maps common spelling / dash / abbreviation variants → canonical lower-case name
ZONE_ALIASES: Dict[str, str] = {
    "ot zone":   "ot zone",
    "ot":        "ot zone",
    "ot-zone":   "ot zone",
    "ot dmz":    "ot dmz",
    "ot-dmz":    "ot dmz",
    "otdmz":     "ot dmz",
    "iot zone":  "iot zone",
    "iot":       "iot zone",
    "iot-zone":  "iot zone",
    "iot dmz":   "iot dmz",
    "iot-dmz":   "iot dmz",
    "iotdmz":    "iot dmz",
    "it zone":   "it zone",
    "it":        "it zone",
    "it-zone":   "it zone",
    "internet":  "internet",
    "untrust":   "internet",
}

_KNOWN_ZONES = set(ZONE_ALIASES.values())


def _canonical_zone(name: str) -> str:
    """Return the canonical lower-case zone name, or the stripped input if unknown."""
    key = str(name).strip().lower()
    return ZONE_ALIASES.get(key, key)


def _is_zone_name(value) -> bool:
    """Return True if value looks like a known zone name."""
    if value is None:
        return False
    if isinstance(value, float) and pd.isna(value):
        return False
    return _canonical_zone(str(value)) in _KNOWN_ZONES


# ─── Cell text → action ───────────────────────────────────────────────────────

# Strip trailing superscript Unicode characters and footnote digits
_FOOTNOTE_RE = re.compile(r"[\u00b9\u00b2\u00b3\u00b0\d]+\s*$")


def _parse_cell_policy(cell) -> Optional[tuple]:
    """
    Interpret a policy matrix cell value.

    Returns (action, deny_severity) or None (skip).
      - "May be allowed" / similar  → ("allow", None)
      - "Should not be allowed"     → ("deny", "HIGH")    — conditional prohibition
      - "Shall not be allowed"      → ("deny", "CRITICAL") — absolute prohibition
      - "Direct access shall not…"  → ("deny", "CRITICAL")
      - Empty / "Out of scope" / diagonal → None (skip)
    """
    if cell is None:
        return None
    if isinstance(cell, float) and pd.isna(cell):
        return None

    text = _FOOTNOTE_RE.sub("", str(cell)).strip().lower()

    if not text or "out of scope" in text:
        return None

    # Allow patterns
    if "may be allowed" in text:
        return ("allow", None)
    if "allowed" in text and "not" not in text:
        return ("allow", None)

    # Deny patterns — "shall" (absolute) takes precedence over "should" (conditional)
    if "shall not be allowed" in text or "direct access shall not be allowed" in text:
        return ("deny", "CRITICAL")
    if "should not be allowed" in text:
        return ("deny", "HIGH")

    logger.debug(f"Unrecognized matrix cell text (skipped): '{cell}'")
    return None


# ─── Grid format ─────────────────────────────────────────────────────────────

def _find_header_row(df: pd.DataFrame) -> Optional[int]:
    """
    Scan the first 6 rows of a dataframe to find the row that contains
    at least 3 known zone names (i.e. the column-header row of the grid).
    Returns the 0-based row index or None.
    """
    for idx in range(min(6, len(df))):
        zone_count = sum(1 for v in df.iloc[idx].tolist() if _is_zone_name(v))
        if zone_count >= 3:
            return idx
    return None


def _parse_grid_sheet(df: pd.DataFrame) -> List[PolicyRule]:
    """
    Parse a zone-pair grid sheet (header=None read) into PolicyRule objects.

    Layout assumed:
      - One row contains destination zone names as column headers
      - Subsequent rows start with a source zone name (col 0),
        followed by policy cell text for each destination zone
    """
    header_row = _find_header_row(df)
    if header_row is None:
        return []

    # Build list of (col_index, canonical_dest_zone)
    dest_cols: List[tuple[int, str]] = []
    for col_idx, val in enumerate(df.iloc[header_row].tolist()):
        if _is_zone_name(val):
            dest_cols.append((col_idx, _canonical_zone(str(val))))

    if not dest_cols:
        return []

    rules: List[PolicyRule] = []
    for row_idx in range(header_row + 1, len(df)):
        row = df.iloc[row_idx].tolist()
        src_raw = row[0] if row else None
        if not _is_zone_name(src_raw):
            continue
        source_zone = _canonical_zone(str(src_raw))

        for col_idx, dest_zone in dest_cols:
            if col_idx >= len(row):
                continue
            result = _parse_cell_policy(row[col_idx])
            if result is None:
                continue
            action, deny_severity = result
            rules.append(PolicyRule(
                source_zone=source_zone,
                dest_zone=dest_zone,
                allowed_ports={"any"},
                allowed_applications={"any"},
                required_profiles={},
                logging_required=True,
                action=action,
                deny_severity=deny_severity,
                description=str(row[col_idx]).strip(),
            ))

    return rules


# ─── Columnar format (legacy) ─────────────────────────────────────────────────

COLUMN_MAP = {
    "source zone":          "source_zone",
    "src zone":             "source_zone",
    "from zone":            "source_zone",
    "destination zone":     "dest_zone",
    "dest zone":            "dest_zone",
    "to zone":              "dest_zone",
    "allowed ports":        "allowed_ports",
    "ports":                "allowed_ports",
    "port":                 "allowed_ports",
    "allowed applications": "allowed_applications",
    "applications":         "allowed_applications",
    "application":          "allowed_applications",
    "app":                  "allowed_applications",
    "av profile":           "av_profile",
    "antivirus profile":    "av_profile",
    "url profile":          "url_profile",
    "url filtering":        "url_profile",
    "log required":         "logging_required",
    "logging required":     "logging_required",
    "logging":              "logging_required",
    "action":               "action",
    "description":          "description",
    "conditions":           "conditions",
    "notes":                "conditions",
}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip().lower() for c in df.columns]
    rename = {c: COLUMN_MAP[c] for c in df.columns if c in COLUMN_MAP}
    return df.rename(columns=rename)


def _parse_set(value) -> set:
    if pd.isna(value) or str(value).strip().lower() in ("", "any", "all"):
        return {"any"}
    return {v.strip().lower() for v in str(value).split(",") if v.strip()}


def _parse_bool(value) -> bool:
    if pd.isna(value):
        return False
    return str(value).strip().lower() in ("yes", "true", "1", "required")


def _parse_action_str(value: str) -> str:
    val = str(value).strip().lower()
    if val in ("allow", "permit"):
        return "allow"
    if val in ("deny", "drop", "block"):
        return "deny"
    logger.warning(f"Unknown action value '{value}', defaulting to 'allow'")
    return "allow"


def _parse_columnar_sheet(df: pd.DataFrame) -> Optional[List[PolicyRule]]:
    """
    Try to parse a sheet as columnar format.
    Returns a list of PolicyRule objects, or None if the sheet lacks
    the required Source Zone / Destination Zone columns.
    """
    df = _normalize_columns(df)
    if "source_zone" not in df.columns or "dest_zone" not in df.columns:
        return None
    if "action" not in df.columns:
        return None

    df = df.dropna(how="all")
    rules: List[PolicyRule] = []
    for idx, row in df.iterrows():
        try:
            rules.append(PolicyRule(
                source_zone=str(row["source_zone"]).strip(),
                dest_zone=str(row["dest_zone"]).strip(),
                allowed_ports=_parse_set(row.get("allowed_ports")),
                allowed_applications=_parse_set(row.get("allowed_applications")),
                required_profiles={
                    "av":  str(row["av_profile"]).strip()
                           if "av_profile" in row and not pd.isna(row.get("av_profile"))
                           else None,
                    "url": str(row["url_profile"]).strip()
                           if "url_profile" in row and not pd.isna(row.get("url_profile"))
                           else None,
                },
                logging_required=_parse_bool(row.get("logging_required", False)),
                action=_parse_action_str(row.get("action", "allow")),
                description=str(row["description"])
                            if "description" in row and not pd.isna(row.get("description"))
                            else None,
                conditions=str(row["conditions"])
                           if "conditions" in row and not pd.isna(row.get("conditions"))
                           else None,
            ))
        except Exception as e:
            logger.warning(f"Skipping matrix row {idx + 2} due to error: {e}")
    return rules


# ─── Zone Assignments loader ──────────────────────────────────────────────────

def load_zone_assignments(filepath: Path) -> Dict[str, str]:
    """
    Read the 'Zone Assignments' sheet (if present).
    Returns a dict mapping interface/VLAN name (lower-case) → canonical zone name.
    """
    try:
        xls = pd.ExcelFile(filepath)
        for sheet in xls.sheet_names:
            if "zone" in sheet.lower() and "assign" in sheet.lower():
                df = pd.read_excel(filepath, sheet_name=sheet, header=0)
                df.columns = [str(c).strip().lower() for c in df.columns]
                # Columns are "Zone" (raw FW zone name) and "ATPSG Zone" (canonical name).
                # After lowercasing: "zone" and "atpsg zone".
                # Pick the ATPSG column first (contains "atpsg"), then treat the
                # remaining zone-ish column as the raw-name column.
                atpsg_col = next((c for c in df.columns if "atpsg" in c), None)
                raw_col   = next((c for c in df.columns if "zone" in c and c != atpsg_col), None)
                # Fallback: if no "atpsg" header, treat first column as raw, second as canonical
                if not atpsg_col and len(df.columns) >= 2:
                    raw_col   = df.columns[0]
                    atpsg_col = df.columns[1]
                if raw_col and atpsg_col:
                    mapping: Dict[str, str] = {}
                    for _, row in df.iterrows():
                        name = str(row[raw_col]).strip()
                        zone = str(row[atpsg_col]).strip()
                        if name and zone and name != "nan" and zone != "nan" and zone != "?":
                            mapping[name.lower()] = _canonical_zone(zone)
                    logger.info(f"Loaded {len(mapping)} zone assignments from '{sheet}'")
                    return mapping
    except Exception as e:
        logger.warning(f"Could not load zone assignments: {e}")
    return {}


# ─── Public entry point ───────────────────────────────────────────────────────

def parse_matrix(filepath: "str | Path") -> List[PolicyRule]:
    """
    Parse a Security Policy Matrix Excel file into PolicyRule objects.

    Tries grid format first (preferred for IT/OT matrices), then falls back
    to columnar format.

    Raises:
        FileNotFoundError: if the file does not exist
        ValueError: if no supported format is detected
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Matrix file not found: {filepath}")

    logger.info(f"Parsing policy matrix from {filepath.name}")
    xls = pd.ExcelFile(filepath)

    # Prioritise sheets with "matrix" in the name for grid detection
    sheet_order = sorted(
        xls.sheet_names,
        key=lambda s: (0 if "matrix" in s.lower() else 1),
    )

    # ── Grid format ────────────────────────────────────────────────
    for sheet in sheet_order:
        df = pd.read_excel(filepath, sheet_name=sheet, header=None)
        rules = _parse_grid_sheet(df)
        if rules:
            logger.info(
                f"Parsed {len(rules)} policy rules (grid format) from sheet '{sheet}'"
            )
            return rules

    # ── Columnar format (fallback) ─────────────────────────────────
    for sheet in xls.sheet_names:
        df = pd.read_excel(filepath, sheet_name=sheet, header=0)
        rules = _parse_columnar_sheet(df)
        if rules is not None:
            logger.info(
                f"Parsed {len(rules)} policy rules (columnar format) from sheet '{sheet}'"
            )
            return rules

    raise ValueError(
        "Could not parse the Security Policy Matrix. Supported formats:\n"
        "  1. Grid format: zone names as row/column headers with cell text such as\n"
        "     'May be allowed' / 'Shall not be allowed' / 'Should not be allowed'\n"
        "  2. Columnar format: columns named 'Source Zone', 'Destination Zone', 'Action'"
    )
