"""
Normalizer
Aligns parsed PolicyRules and FirewallRules into a consistent schema
before they are handed to the validation engine.

Key normalizations:
  - Port representation: "tcp/443" → "443", "application-default" → "app-default"
  - Zone name casing: "Trust" == "trust"
  - "any" wildcard handling across both models
  - Application-default service resolution hint
  - Zone translation: raw firewall zone names are mapped to canonical ATPSG
    zone names via the Zone Assignments sheet before comparison with the matrix
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from app.models import PolicyRule, FirewallRule

logger = logging.getLogger(__name__)


# Common Palo Alto service aliases → normalized port string
SERVICE_ALIAS_MAP = {
    "application-default": "app-default",
    "application default":  "app-default",
    "any":                  "any",
}


def _normalize_port(service: str) -> str:
    """
    Normalize a service/port string to a bare port number where possible.
    Examples:
      "tcp/443"   → "443"
      "udp/53"    → "53"
      "443"       → "443"
      "application-default" → "app-default"
    """
    service = service.strip().lower()
    if service in SERVICE_ALIAS_MAP:
        return SERVICE_ALIAS_MAP[service]
    match = re.match(r"(?:tcp|udp)/(\d+)", service)
    if match:
        return match.group(1)
    return service


def _normalize_ports(ports: set) -> set:
    return {_normalize_port(p) for p in ports}


def _normalize_zones(zones: set, zone_map: Optional[Dict[str, str]] = None) -> set:
    """
    Lower-case each zone name, then translate via *zone_map* if provided.

    *zone_map* maps raw firewall zone names (lower-case) → canonical ATPSG
    zone names (e.g. "outside" → "it zone", "ot-dmz-sr" → "ot dmz").
    Zones not present in the map are kept as-is (already lower-cased).
    """
    result = set()
    for z in zones:
        z_lower = z.strip().lower()
        if zone_map:
            z_lower = zone_map.get(z_lower, z_lower)
        result.add(z_lower)
    return result


def normalize_policy_rules(rules: List[PolicyRule]) -> List[PolicyRule]:
    """Normalize all PolicyRule objects in-place."""
    for rule in rules:
        rule.source_zone = rule.source_zone.strip().lower()
        rule.dest_zone = rule.dest_zone.strip().lower()
        rule.allowed_ports = _normalize_ports(rule.allowed_ports)
        rule.allowed_applications = {a.strip().lower() for a in rule.allowed_applications}
        rule.action = rule.action.strip().lower()
    logger.info(f"Normalized {len(rules)} policy rules")
    return rules


def normalize_firewall_rules(
    rules: List[FirewallRule],
    zone_map: Optional[Dict[str, str]] = None,
) -> List[FirewallRule]:
    """
    Normalize all FirewallRule objects in-place.

    Args:
        rules:    List of FirewallRule objects from the rulebase parser.
        zone_map: Optional mapping of raw firewall zone names → canonical
                  ATPSG zone names loaded from the Zone Assignments sheet.
                  When supplied, source/dest zones are translated so they
                  match the policy matrix zone names before validation.
    """
    if zone_map:
        logger.info(f"Applying zone map with {len(zone_map)} entries to firewall rules")
    for rule in rules:
        rule.source_zones = _normalize_zones(rule.source_zones, zone_map)
        rule.dest_zones   = _normalize_zones(rule.dest_zones,   zone_map)
        rule.services      = _normalize_ports(rule.services)
        rule.applications  = {a.strip().lower() for a in rule.applications}
        rule.action        = rule.action.strip().lower()
    logger.info(f"Normalized {len(rules)} firewall rules")
    return rules


def normalize_all(
    policy_rules: List[PolicyRule],
    firewall_rules: List[FirewallRule],
    zone_map: Optional[Dict[str, str]] = None,
) -> Tuple[List[PolicyRule], List[FirewallRule]]:
    """
    Entry point: normalize both sets before validation.

    Args:
        policy_rules:   From the matrix parser — zones already canonical.
        firewall_rules: From the rulebase parser — zones may be raw names.
        zone_map:       From load_zone_assignments() — translates raw
                        firewall zone names to canonical ATPSG zone names.

    Returns:
        Tuple of normalized (policy_rules, firewall_rules).
    """
    policy_rules   = normalize_policy_rules(policy_rules)
    firewall_rules = normalize_firewall_rules(firewall_rules, zone_map)
    return policy_rules, firewall_rules

