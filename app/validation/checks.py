"""
Validation Checks
Four independent check modules consumed by the validation engine.
Each returns a list of Finding objects.
"""

import logging
from typing import List

from app.models import PolicyRule, FirewallRule, Finding

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _zones_match(fw_src: set, fw_dst: set, policy: PolicyRule) -> bool:
    """
    Check if a firewall rule's zone pair overlaps with a policy rule's zone pair.
    Handles 'any' wildcard on the firewall rule side.
    """
    src_match = "any" in fw_src or policy.source_zone in fw_src
    dst_match = "any" in fw_dst or policy.dest_zone in fw_dst
    return src_match and dst_match


def _find_matching_policies(
    fw_rule: FirewallRule,
    policy_rules: List[PolicyRule],
) -> List[PolicyRule]:
    """Return all policy rules whose zone pair overlaps with this firewall rule."""
    return [
        p for p in policy_rules
        if _zones_match(fw_rule.source_zones, fw_rule.dest_zones, p)
    ]


# ─────────────────────────────────────────────────────────────
# CHECK 1: UNAUTHORIZED FLOW
# Rules on the firewall with no matching entry in the matrix
# ─────────────────────────────────────────────────────────────

def check_unauthorized_flows(
    firewall_rules: List[FirewallRule],
    policy_rules: List[PolicyRule],
) -> List[Finding]:
    """
    Flag any firewall rule whose source→dest zone combination
    has no entry in the security policy matrix.
    Only flags ALLOW rules — deny rules for unlisted flows are expected.
    """
    findings = []
    for fw_rule in firewall_rules:
        if not fw_rule.enabled:
            continue
        if fw_rule.action != "allow":
            continue
        matching = _find_matching_policies(fw_rule, policy_rules)
        if not matching:
            findings.append(Finding(
                rule_name=fw_rule.rule_name,
                finding_type="UNAUTHORIZED_FLOW",
                severity=Finding.SEVERITY_CRITICAL,
                description=(
                    f"Rule '{fw_rule.rule_name}' permits traffic from zone(s) "
                    f"{fw_rule.source_zones} to {fw_rule.dest_zones}, but this "
                    f"zone pair has no entry in the Security Policy Matrix."
                ),
                details={
                    "source_zones": list(fw_rule.source_zones),
                    "dest_zones":   list(fw_rule.dest_zones),
                    "services":     list(fw_rule.services),
                    "rule_index":   fw_rule.rule_index,
                },
                remediation=(
                    "Review whether this traffic flow should be authorized. "
                    "If legitimate, add it to the Security Policy Matrix. "
                    "If not, remove or disable the rule."
                ),
            ))
    logger.info(f"Unauthorized flow check: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 2: CONDITION VIOLATIONS
# Rule exists in matrix but doesn't comply with the conditions
# ─────────────────────────────────────────────────────────────

def check_condition_violations(
    firewall_rules: List[FirewallRule],
    policy_rules: List[PolicyRule],
) -> List[Finding]:
    """
    For each firewall rule that matches a policy zone pair, verify:
      - Action matches the policy
      - Ports are within the allowed set (if matrix restricts ports)
      - AV profile is applied if required
      - URL profile is applied if required
      - Logging is enabled if required
    """
    findings = []

    for fw_rule in firewall_rules:
        if not fw_rule.enabled:
            continue

        matching_policies = _find_matching_policies(fw_rule, policy_rules)
        if not matching_policies:
            continue  # Handled by unauthorized flow check

        for policy in matching_policies:

            # 1. Action mismatch
            if fw_rule.action != policy.action:
                findings.append(Finding(
                    rule_name=fw_rule.rule_name,
                    finding_type="CONDITION_VIOLATION",
                    severity=Finding.SEVERITY_CRITICAL,
                    description=(
                        f"Rule '{fw_rule.rule_name}' action is '{fw_rule.action}' "
                        f"but the matrix requires '{policy.action}' for "
                        f"{policy.source_zone}→{policy.dest_zone}."
                    ),
                    details={"expected_action": policy.action, "actual_action": fw_rule.action},
                    remediation=f"Change rule action to '{policy.action}' or update the matrix.",
                ))

            # 2. Port violation (only if matrix specifies non-any ports)
            if "any" not in policy.allowed_ports:
                disallowed_ports = fw_rule.services - policy.allowed_ports - {"any", "app-default"}
                if disallowed_ports:
                    findings.append(Finding(
                        rule_name=fw_rule.rule_name,
                        finding_type="CONDITION_VIOLATION",
                        severity=Finding.SEVERITY_HIGH,
                        description=(
                            f"Rule '{fw_rule.rule_name}' allows services {disallowed_ports} "
                            f"which are not authorized by the matrix for "
                            f"{policy.source_zone}→{policy.dest_zone} "
                            f"(allowed: {policy.allowed_ports})."
                        ),
                        details={
                            "disallowed_services": list(disallowed_ports),
                            "allowed_ports":       list(policy.allowed_ports),
                        },
                        remediation="Restrict the rule's services to match the policy matrix.",
                    ))

            # 3. Missing AV profile
            required_av = policy.required_profiles.get("av")
            if required_av and not fw_rule.av_profile and not fw_rule.security_profile_group:
                findings.append(Finding(
                    rule_name=fw_rule.rule_name,
                    finding_type="CONDITION_VIOLATION",
                    severity=Finding.SEVERITY_HIGH,
                    description=(
                        f"Rule '{fw_rule.rule_name}' is missing the required AV profile "
                        f"'{required_av}' for {policy.source_zone}→{policy.dest_zone}."
                    ),
                    details={"required_av_profile": required_av},
                    remediation=f"Apply AV profile '{required_av}' or a security profile group to the rule.",
                ))

            # 4. Missing URL profile
            required_url = policy.required_profiles.get("url")
            if required_url and not fw_rule.url_profile and not fw_rule.security_profile_group:
                findings.append(Finding(
                    rule_name=fw_rule.rule_name,
                    finding_type="CONDITION_VIOLATION",
                    severity=Finding.SEVERITY_HIGH,
                    description=(
                        f"Rule '{fw_rule.rule_name}' is missing the required URL profile "
                        f"'{required_url}' for {policy.source_zone}→{policy.dest_zone}."
                    ),
                    details={"required_url_profile": required_url},
                    remediation=f"Apply URL filtering profile '{required_url}' to the rule.",
                ))

            # 5. Logging not enabled when required
            if policy.logging_required and not fw_rule.log_at_session_end and not fw_rule.log_forwarding:
                findings.append(Finding(
                    rule_name=fw_rule.rule_name,
                    finding_type="CONDITION_VIOLATION",
                    severity=Finding.SEVERITY_MEDIUM,
                    description=(
                        f"Rule '{fw_rule.rule_name}' does not have logging enabled, "
                        f"but the matrix requires logging for {policy.source_zone}→{policy.dest_zone}."
                    ),
                    details={"logging_required": True},
                    remediation="Enable 'Log At Session End' or configure a Log Forwarding profile.",
                ))

    logger.info(f"Condition violation check: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 3: MISSING IMPLEMENTATION
# Matrix entries with no corresponding firewall rule
# ─────────────────────────────────────────────────────────────

def check_missing_implementations(
    firewall_rules: List[FirewallRule],
    policy_rules: List[PolicyRule],
) -> List[Finding]:
    """
    For each ALLOW entry in the policy matrix, check that at least one
    enabled firewall rule covers that zone pair.
    """
    findings = []
    for policy in policy_rules:
        if policy.action != "allow":
            continue
        covered = any(
            _zones_match(fw.source_zones, fw.dest_zones, policy)
            for fw in firewall_rules
            if fw.enabled
        )
        if not covered:
            findings.append(Finding(
                rule_name=None,
                finding_type="MISSING_IMPLEMENTATION",
                severity=Finding.SEVERITY_MEDIUM,
                description=(
                    f"The matrix authorizes traffic from '{policy.source_zone}' to "
                    f"'{policy.dest_zone}' but no enabled firewall rule implements this flow."
                ),
                details={
                    "source_zone":  policy.source_zone,
                    "dest_zone":    policy.dest_zone,
                    "allowed_ports": list(policy.allowed_ports),
                },
                remediation=(
                    "Create a firewall rule implementing this authorized flow, "
                    "or remove it from the matrix if no longer required."
                ),
            ))
    logger.info(f"Missing implementation check: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 4: HYGIENE
# Disabled rules, any-any permits, shadowed rules
# ─────────────────────────────────────────────────────────────

def check_hygiene(firewall_rules: List[FirewallRule]) -> List[Finding]:
    """
    Hygiene checks — not policy violations but security/operational risks:
      - Disabled rules still present (stale config)
      - Any-Any permit rules (overly permissive)
      - Rules shadowed by a broader rule above them
    """
    findings = []

    for fw_rule in firewall_rules:

        # Disabled rules
        if not fw_rule.enabled:
            findings.append(Finding(
                rule_name=fw_rule.rule_name,
                finding_type="HYGIENE_DISABLED_RULE",
                severity=Finding.SEVERITY_LOW,
                description=(
                    f"Rule '{fw_rule.rule_name}' is disabled. Stale disabled rules "
                    f"increase audit complexity and may be re-enabled accidentally."
                ),
                details={"rule_index": fw_rule.rule_index},
                remediation="Remove disabled rules that are no longer needed.",
            ))
            continue

        # Any-Any permit
        if (
            fw_rule.action == "allow"
            and "any" in fw_rule.source_zones
            and "any" in fw_rule.dest_zones
            and "any" in fw_rule.services
        ):
            findings.append(Finding(
                rule_name=fw_rule.rule_name,
                finding_type="HYGIENE_ANY_ANY_PERMIT",
                severity=Finding.SEVERITY_CRITICAL,
                description=(
                    f"Rule '{fw_rule.rule_name}' permits ALL traffic from ANY zone to ANY zone "
                    f"on ANY service. This is extremely overly permissive."
                ),
                details={"rule_index": fw_rule.rule_index},
                remediation="Replace with specific zone-pair rules matching the policy matrix.",
            ))

    # Shadowed rules — a rule is shadowed if an identical or broader rule appears before it
    enabled_rules = [r for r in firewall_rules if r.enabled]
    for i, rule in enumerate(enabled_rules):
        for j, earlier_rule in enumerate(enabled_rules[:i]):
            if _is_shadowed(rule, earlier_rule):
                findings.append(Finding(
                    rule_name=rule.rule_name,
                    finding_type="HYGIENE_SHADOWED_RULE",
                    severity=Finding.SEVERITY_LOW,
                    description=(
                        f"Rule '{rule.rule_name}' (index {rule.rule_index}) is shadowed by "
                        f"'{earlier_rule.rule_name}' (index {earlier_rule.rule_index}). "
                        f"It will never be matched."
                    ),
                    details={
                        "shadowed_by": earlier_rule.rule_name,
                        "rule_index":  rule.rule_index,
                    },
                    remediation=(
                        f"Remove or reorder '{rule.rule_name}', or narrow '{earlier_rule.rule_name}'."
                    ),
                ))
                break  # Only report the first shadowing rule

    logger.info(f"Hygiene check: {len(findings)} findings")
    return findings


def _is_shadowed(rule: FirewallRule, broader: FirewallRule) -> bool:
    """
    Returns True if 'broader' completely covers 'rule' (i.e., rule will never match).
    Conservative check — only flags when all dimensions are superset or equal.
    """
    def covers(broader_set: set, specific_set: set) -> bool:
        return "any" in broader_set or specific_set.issubset(broader_set)

    return (
        broader.action == rule.action
        and covers(broader.source_zones, rule.source_zones)
        and covers(broader.dest_zones, rule.dest_zones)
        and covers(broader.services, rule.services)
        and covers(broader.applications, rule.applications)
    )
