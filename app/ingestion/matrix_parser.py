"""
Matrix Parser
Reads the Security Policy Matrix from an Excel (.xlsx) file and converts
each row into a PolicyRule object.

Expected Excel columns (case-insensitive, flexible mapping):
  - Source Zone
  - Destination Zone
  - Allowed Ports        (comma-separated: "443,80" or "any")
  - Allowed Applications (comma-separated: "ssl,web-browsing" or "any")
  - AV Profile           (profile name or blank)
  - URL Profile          (profile name or blank)
  - Log Required         (yes/no/true/false)
  - Action               (allow/deny)
  - Description          (optional free text)
  - Conditions           (optional free text)
"""

import logging
from pathlib import Path
from typing import List

import pandas as pd

from app.models import PolicyRule

logger = logging.getLogger(__name__)

# Flexible column name mapping - normalizes common variations
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
    """Lowercase and strip column names, then remap to internal names."""
    df.columns = [c.strip().lower() for c in df.columns]
    rename = {c: COLUMN_MAP[c] for c in df.columns if c in COLUMN_MAP}
    return df.rename(columns=rename)


def _parse_set(value: str) -> set:
    """Convert comma-separated string to a normalized set."""
    if pd.isna(value) or str(value).strip().lower() in ("", "any", "all"):
        return {"any"}
    return {v.strip().lower() for v in str(value).split(",") if v.strip()}


def _parse_bool(value) -> bool:
    """Convert yes/no/true/false/1/0 to bool."""
    if pd.isna(value):
        return False
    return str(value).strip().lower() in ("yes", "true", "1", "required")


def _parse_action(value: str) -> str:
    val = str(value).strip().lower()
    if val in ("allow", "permit"):
        return "allow"
    if val in ("deny", "drop", "block"):
        return "deny"
    logger.warning(f"Unknown action value '{value}', defaulting to 'allow'")
    return "allow"


def parse_matrix(filepath: str | Path) -> List[PolicyRule]:
    """
    Parse a Security Policy Matrix Excel file.

    Args:
        filepath: Path to the .xlsx file

    Returns:
        List of PolicyRule objects

    Raises:
        ValueError: If required columns are missing
        FileNotFoundError: If the file doesn't exist
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Matrix file not found: {filepath}")

    logger.info(f"Parsing policy matrix from {filepath.name}")

    # Read all sheets, use the first one that has data resembling a matrix
    xls = pd.ExcelFile(filepath)
    df = None
    for sheet in xls.sheet_names:
        candidate = pd.read_excel(filepath, sheet_name=sheet, header=0)
        candidate = _normalize_columns(candidate)
        if "source_zone" in candidate.columns and "dest_zone" in candidate.columns:
            df = candidate
            logger.info(f"Using sheet: '{sheet}'")
            break

    if df is None:
        raise ValueError(
            "Could not find a sheet with 'Source Zone' and 'Destination Zone' columns. "
            "Please check your matrix format."
        )

    # Drop fully empty rows
    df = df.dropna(how="all")

    # Validate required columns
    required = {"source_zone", "dest_zone", "action"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Matrix is missing required columns: {missing}")

    rules: List[PolicyRule] = []
    for idx, row in df.iterrows():
        try:
            rule = PolicyRule(
                source_zone=str(row["source_zone"]).strip(),
                dest_zone=str(row["dest_zone"]).strip(),
                allowed_ports=_parse_set(row.get("allowed_ports")),
                allowed_applications=_parse_set(row.get("allowed_applications")),
                required_profiles={
                    "av":  str(row["av_profile"]).strip() if "av_profile" in row and not pd.isna(row.get("av_profile")) else None,
                    "url": str(row["url_profile"]).strip() if "url_profile" in row and not pd.isna(row.get("url_profile")) else None,
                },
                logging_required=_parse_bool(row.get("logging_required", False)),
                action=_parse_action(row.get("action", "allow")),
                description=str(row["description"]) if "description" in row and not pd.isna(row.get("description")) else None,
                conditions=str(row["conditions"]) if "conditions" in row and not pd.isna(row.get("conditions")) else None,
            )
            rules.append(rule)
        except Exception as e:
            logger.warning(f"Skipping matrix row {idx + 2} due to error: {e}")

    logger.info(f"Parsed {len(rules)} policy rules from matrix")
    return rules
