"""
Normalizer
Aligns parsed PolicyRules and FirewallRules into a consistent schema
before they are handed to the validation engine.

Key normalizations:
  - Port representation: "tcp/443" → "443", "application-default" → "app-default"
  - Zone name casing: "Trust" == "trust"
  - "any" wildcard handling across both models
  - Application-default service resolution hint
"""

import logging
import re
from typing import List, Tuple

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


def _normalize_zones(zones: set) -> set:
    return {z.strip().lower() for z in zones}


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


def normalize_firewall_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Normalize all FirewallRule objects in-place."""
    for rule in rules:
        rule.source_zones = _normalize_zones(rule.source_zones)
        rule.dest_zones = _normalize_zones(rule.dest_zones)
        rule.services = _normalize_ports(rule.services)
        rule.applications = {a.strip().lower() for a in rule.applications}
        rule.action = rule.action.strip().lower()
    logger.info(f"Normalized {len(rules)} firewall rules")
    return rules


def normalize_all(
    policy_rules: List[PolicyRule],
    firewall_rules: List[FirewallRule],
) -> Tuple[List[PolicyRule], List[FirewallRule]]:
    """
    Entry point: normalize both sets before validation.
    Returns the normalized lists (mutates in-place and returns for convenience).
    """
    policy_rules = normalize_policy_rules(policy_rules)
    firewall_rules = normalize_firewall_rules(firewall_rules)
    return policy_rules, firewall_rules
