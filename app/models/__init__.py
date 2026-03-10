from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class PolicyRule:
    """
    Represents a single row from the Security Policy Matrix (Excel).
    Defines what traffic is ALLOWED according to policy.
    """
    source_zone: str
    dest_zone: str
    allowed_ports: Set[str]          # e.g. {"443", "80", "8080"} or {"any"}
    allowed_applications: Set[str]   # e.g. {"ssl", "web-browsing"} or {"any"}
    required_profiles: dict          # e.g. {"av": "strict", "url": "default"}
    logging_required: bool
    action: str                      # "allow" or "deny"
    description: Optional[str] = None
    conditions: Optional[str] = None # free-text notes from matrix
    # Severity of a violation when a FW rule permits this denied flow:
    # "HIGH" for "Should not be allowed", "CRITICAL" for "Shall not be allowed"
    deny_severity: Optional[str] = None


@dataclass
class FirewallRule:
    """
    Represents a single rule extracted from the Palo Alto rulebase CSV export.
    """
    rule_name: str
    source_zones: Set[str]
    dest_zones: Set[str]
    source_addresses: Set[str]
    dest_addresses: Set[str]
    applications: Set[str]
    services: Set[str]               # ports/protocols e.g. {"tcp/443", "application-default"}
    action: str                      # "allow" or "deny"
    security_profile_group: Optional[str]
    av_profile: Optional[str]
    url_profile: Optional[str]
    log_forwarding: Optional[str]
    log_at_session_end: bool
    enabled: bool
    rule_index: int                  # original row order in rulebase


@dataclass
class Finding:
    """
    A single compliance finding produced by the validation engine.
    """
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"

    rule_name: Optional[str]        # None for missing-implementation findings
    finding_type: str               # e.g. "UNAUTHORIZED_FLOW", "CONDITION_VIOLATION"
    severity: str
    description: str
    details: dict = field(default_factory=dict)
    remediation: str = ""
