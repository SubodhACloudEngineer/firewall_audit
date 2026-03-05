"""
Rulebase Parser
Reads a Palo Alto firewall rulebase CSV export and converts each row
into a FirewallRule object.

Palo Alto CSV export columns (from Panorama or device):
  Name, Source Zone, Destination Zone, Source Address, Destination Address,
  Application, Service, Action, Profile Group, AV Profile, URL Profile,
  Log Forwarding, Log At Session End, Disabled, Description

The parser handles both Panorama exports and per-device exports.
Column names may vary slightly — flexible mapping is used.
"""

import logging
from pathlib import Path
from typing import List, Optional

import pandas as pd

from app.models import FirewallRule

logger = logging.getLogger(__name__)

# Flexible column name mapping for Palo Alto CSV variations
COLUMN_MAP = {
    "name":                   "rule_name",
    "rule name":              "rule_name",
    "rulename":               "rule_name",
    "source zone":            "source_zones",
    "from":                   "source_zones",
    "src zone":               "source_zones",
    "destination zone":       "dest_zones",
    "to":                     "dest_zones",
    "dst zone":               "dest_zones",
    "source address":         "source_addresses",
    "source":                 "source_addresses",
    "src":                    "source_addresses",
    "destination address":    "dest_addresses",
    "destination":            "dest_addresses",
    "dst":                    "dest_addresses",
    "application":            "applications",
    "applications":           "applications",
    "service":                "services",
    "action":                 "action",
    "profile group":          "security_profile_group",
    "profile-group":          "security_profile_group",
    "security profile group": "security_profile_group",
    "av profile":             "av_profile",
    "antivirus":              "av_profile",
    "url profile":            "url_profile",
    "url filtering profile":  "url_profile",
    "log forwarding":         "log_forwarding",
    "log-forwarding":         "log_forwarding",
    "log at session end":     "log_at_session_end",
    "log-at-session-end":     "log_at_session_end",
    "disabled":               "enabled",   # inverted below
    "enabled":                "enabled",
    "description":            "description",
}

# Palo Alto uses semicolons to separate multi-value fields in CSV exports
MULTI_VALUE_SEPARATOR = ";"


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip().lower() for c in df.columns]
    rename = {c: COLUMN_MAP[c] for c in df.columns if c in COLUMN_MAP}
    return df.rename(columns=rename)


def _parse_multi(value, separator: str = MULTI_VALUE_SEPARATOR) -> set:
    """Parse semicolon or comma-separated multi-value field into a set."""
    if pd.isna(value) or str(value).strip().lower() in ("", "any"):
        return {"any"}
    # Try semicolon first (Panorama), then comma
    raw = str(value).strip()
    if separator in raw:
        parts = raw.split(separator)
    else:
        parts = raw.split(",")
    return {p.strip().lower() for p in parts if p.strip()}


def _parse_bool_enabled(value, column_was_disabled: bool = False) -> bool:
    """
    Parse enabled/disabled status.
    Palo Alto CSV exports 'disabled' column with 'yes'/'no'.
    We invert if the source column was 'disabled'.
    """
    if pd.isna(value):
        return True  # default to enabled if not specified
    bool_val = str(value).strip().lower() in ("yes", "true", "1")
    return not bool_val if column_was_disabled else bool_val


def _parse_action(value: str) -> str:
    val = str(value).strip().lower()
    return "deny" if val in ("deny", "drop", "block") else "allow"


def _extract_optional_str(row, key: str) -> Optional[str]:
    val = row.get(key)
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    return str(val).strip() or None


def parse_rulebase(filepath: str | Path) -> List[FirewallRule]:
    """
    Parse a Palo Alto rulebase CSV export.

    Args:
        filepath: Path to the .csv file

    Returns:
        List of FirewallRule objects ordered by rule index (rulebase order)

    Raises:
        ValueError: If required columns are missing
        FileNotFoundError: If the file doesn't exist
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Rulebase file not found: {filepath}")

    logger.info(f"Parsing rulebase from {filepath.name}")

    # Try to detect encoding (Panorama exports sometimes use UTF-16)
    encodings = ["utf-8", "utf-16", "latin-1"]
    df = None
    for enc in encodings:
        try:
            df = pd.read_csv(filepath, encoding=enc, skip_blank_lines=True)
            break
        except (UnicodeDecodeError, pd.errors.ParserError):
            continue

    if df is None:
        raise ValueError(f"Could not parse CSV file {filepath.name}. Check encoding.")

    original_columns = list(df.columns)
    df = _normalize_columns(df)

    # Detect if original 'disabled' column was used (so we invert the boolean)
    disabled_col_used = any(
        c.strip().lower() == "disabled" for c in original_columns
    )

    # Drop fully empty rows
    df = df.dropna(how="all")

    # Validate minimum required columns
    required = {"rule_name", "source_zones", "dest_zones", "action"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Rulebase CSV is missing required columns: {missing}. "
            f"Found columns: {list(df.columns)}"
        )

    rules: List[FirewallRule] = []
    for idx, row in df.iterrows():
        try:
            enabled_raw = row.get("enabled")
            rule = FirewallRule(
                rule_name=str(row["rule_name"]).strip(),
                source_zones=_parse_multi(row["source_zones"]),
                dest_zones=_parse_multi(row["dest_zones"]),
                source_addresses=_parse_multi(row.get("source_addresses", "any")),
                dest_addresses=_parse_multi(row.get("dest_addresses", "any")),
                applications=_parse_multi(row.get("applications", "any")),
                services=_parse_multi(row.get("services", "any")),
                action=_parse_action(row["action"]),
                security_profile_group=_extract_optional_str(row, "security_profile_group"),
                av_profile=_extract_optional_str(row, "av_profile"),
                url_profile=_extract_optional_str(row, "url_profile"),
                log_forwarding=_extract_optional_str(row, "log_forwarding"),
                log_at_session_end=_parse_bool_enabled(
                    row.get("log_at_session_end", True)
                ),
                enabled=_parse_bool_enabled(enabled_raw, disabled_col_used),
                rule_index=idx,
            )
            rules.append(rule)
        except Exception as e:
            logger.warning(f"Skipping rulebase row {idx + 2} due to error: {e}")

    logger.info(f"Parsed {len(rules)} firewall rules from rulebase")
    return rules
