"""
Validation Checks
Four independent check modules consumed by the validation engine.
Each returns a list of Finding objects.
"""

import logging
from typing import Dict, List, Tuple

from app.models import PolicyRule, FirewallRule, Finding

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def expand_zone_pairs(source_zones: set, dest_zones: set) -> List[Tuple[str, str]]:
    """
    Return the Cartesian product of source and destination zones.

    A rule with source=[A, B] and dest=[X, Y] expands to:
      [(A, X), (A, Y), (B, X), (B, Y)]

    Each pair is evaluated independently by check_unauthorized_flows and
    check_condition_violations so that a single rule covering multiple zones
    cannot hide an unauthorized or misconfigured (src, dst) combination.
    """
    return [(src, dst) for src in sorted(source_zones) for dst in sorted(dest_zones)]


def _pair_matches_policy(src: str, dst: str, policy: PolicyRule) -> bool:
    """
    Check if a specific (src, dst) zone pair matches a policy rule.
    'any' on the firewall side acts as a wildcard covering all policy zones.
    """
    src_match = src == "any" or src == policy.source_zone
    dst_match = dst == "any" or dst == policy.dest_zone
    return src_match and dst_match


def _zones_match(fw_src: set, fw_dst: set, policy: PolicyRule) -> bool:
    """
    Check if a firewall rule's zone sets overlap with a policy rule's zone pair.
    Handles 'any' wildcard on the firewall rule side.
    Used by check_missing_implementations which iterates over policies.
    """
    src_match = "any" in fw_src or policy.source_zone in fw_src
    dst_match = "any" in fw_dst or policy.dest_zone in fw_dst
    return src_match and dst_match


# ─────────────────────────────────────────────────────────────
# CHECK 1: UNAUTHORIZED FLOW
# Rules on the firewall with no matching entry in the matrix
# ─────────────────────────────────────────────────────────────

def check_unauthorized_flows(
    firewall_rules: List[FirewallRule],
    policy_rules: List[PolicyRule],
) -> List[Finding]:
    """
    For each (src, dst) pair produced by Cartesian expansion of a firewall
    allow rule's zones, flag any pair that has no matching entry in the
    security policy matrix.

    Multi-zone rules are fully expanded so that a single rule covering zones
    [A, B] → [X, Y] is evaluated as four independent pairs. Only authorized
    pairs (those present in the matrix) are exempt; each unauthorized pair
    generates its own CRITICAL finding.
    """
    findings = []
    for fw_rule in firewall_rules:
        if not fw_rule.enabled:
            continue
        if fw_rule.action != "allow":
            continue
        for src, dst in expand_zone_pairs(fw_rule.source_zones, fw_rule.dest_zones):
            if not any(_pair_matches_policy(src, dst, p) for p in policy_rules):
                findings.append(Finding(
                    rule_name=fw_rule.rule_name,
                    finding_type="UNAUTHORIZED_FLOW",
                    severity=Finding.SEVERITY_CRITICAL,
                    description=(
                        f"Rule '{fw_rule.rule_name}' permits traffic from zone '{src}' "
                        f"to '{dst}', but this zone pair has no entry in the "
                        f"Security Policy Matrix."
                    ),
                    details={
                        "source_zone":  src,
                        "dest_zone":    dst,
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
    For each (src, dst) pair produced by Cartesian expansion of a firewall
    allow rule's zones, find matching policies and verify:
      - Action matches the policy
      - Ports are within the allowed set (if matrix restricts ports)
      - AV profile is applied if required
      - URL profile is applied if required
      - Logging is enabled if required

    Each pair is evaluated independently so that condition violations for one
    (src, dst) combination do not suppress findings for another.
    """
    findings = []

    for fw_rule in firewall_rules:
        if not fw_rule.enabled:
            continue
        if fw_rule.action != "allow":
            # Deny rules in the rulebase are not audited
            continue

        for src, dst in expand_zone_pairs(fw_rule.source_zones, fw_rule.dest_zones):
            matching_policies = [
                p for p in policy_rules if _pair_matches_policy(src, dst, p)
            ]
            if not matching_policies:
                continue  # Handled by unauthorized flow check

            for policy in matching_policies:

                # 1. Action mismatch — FW allows a flow the matrix says should be denied.
                # Severity comes from the matrix cell wording:
                #   "Should not be allowed" → HIGH, "Shall not be allowed" → CRITICAL
                if fw_rule.action != policy.action:
                    mismatch_severity = policy.deny_severity or Finding.SEVERITY_CRITICAL
                    findings.append(Finding(
                        rule_name=fw_rule.rule_name,
                        finding_type="CONDITION_VIOLATION",
                        severity=mismatch_severity,
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
# Disabled rules and shadowed rules
# ─────────────────────────────────────────────────────────────

def check_hygiene(firewall_rules: List[FirewallRule]) -> List[Finding]:
    """
    Hygiene checks — not policy violations but security/operational risks:
      - Disabled rules still present (stale config)
      - Rules shadowed by a broader rule above them

    Note: any-zone permit detection ("any" in source or destination zone) is
    handled by the validation engine as a pre-check step *before* this function
    is called (see engine.py run_audit). Rules with "any" zones receive an
    immediate CRITICAL finding there and are not re-checked here.
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


# ─────────────────────────────────────────────────────────────
# CHECK 5: INTRA-ZONE LATERAL MOVEMENT
# Cross-sub-zone traffic within the same canonical ATPSG zone
# ─────────────────────────────────────────────────────────────

def check_intra_zone_lateral_movement(
    firewall_rules: List[FirewallRule],
    zone_map: Dict[str, str],
) -> List[Finding]:
    """
    Detect cross-sub-zone lateral movement within the same canonical ATPSG zone.

    Context: the Security Policy Matrix contains a cell for "OT Zone → OT Zone"
    that states "Within a shop may be allowed; Between shops should not be allowed."
    After zone normalisation, multiple raw firewall zones (OT-AD, OT-PA, OT-PR, …)
    all collapse to the single canonical name "ot zone", making the standard
    Cartesian checks blind to cross-sub-zone flows.

    This check re-examines each allow rule using the pre-translation zone names
    stored in FirewallRule.raw_source_zones / raw_dest_zones:

      - For each canonical ATPSG zone that appears on both the source and
        destination sides of the rule, build the Cartesian product of the raw
        sub-zone names.
      - Pairs where raw_src == raw_dst are within the same sub-zone ("same shop")
        and are allowed.
      - Pairs where raw_src != raw_dst cross sub-zone boundaries ("between shops")
        and are flagged as HIGH.

    Example:
      Rule src={ot-pa, ot-pr} dst={ot-pa, ot-pr} with zone_map mapping both to
      "ot zone" → 2 HIGH findings: (ot-pa → ot-pr) and (ot-pr → ot-pa).
      Pairs (ot-pa → ot-pa) and (ot-pr → ot-pr) are not flagged.

    Requires zone_map to be non-empty; if no zone_map is provided (empty dict)
    each raw zone maps to itself so no collapse occurs and no findings are raised.
    """
    findings = []
    for rule in firewall_rules:
        if not rule.enabled:
            continue
        if rule.action != "allow":
            continue
        if not rule.raw_source_zones or not rule.raw_dest_zones:
            continue  # raw zones not populated (pre-normalizer path); skip

        # Group raw source and dest zones by canonical ATPSG zone name
        src_by_canonical: Dict[str, set] = {}
        for raw in rule.raw_source_zones:
            canonical = zone_map.get(raw, raw)
            src_by_canonical.setdefault(canonical, set()).add(raw)

        dst_by_canonical: Dict[str, set] = {}
        for raw in rule.raw_dest_zones:
            canonical = zone_map.get(raw, raw)
            dst_by_canonical.setdefault(canonical, set()).add(raw)

        # For each canonical zone present on both sides, check cross-sub-zone pairs
        for canonical, src_raws in src_by_canonical.items():
            dst_raws = dst_by_canonical.get(canonical)
            if not dst_raws:
                continue

            for raw_src in sorted(src_raws):
                for raw_dst in sorted(dst_raws):
                    if raw_src == raw_dst:
                        continue  # same sub-zone → within-shop, allowed
                    findings.append(Finding(
                        rule_name=rule.rule_name,
                        finding_type="INTRA_ZONE_LATERAL_MOVEMENT",
                        severity=Finding.SEVERITY_HIGH,
                        description=(
                            f"Rule '{rule.rule_name}' permits lateral movement from "
                            f"sub-zone '{raw_src}' to '{raw_dst}'. Both map to canonical "
                            f"zone '{canonical}'. Cross-sub-zone traffic should not be allowed."
                        ),
                        details={
                            "raw_source_zone": raw_src,
                            "raw_dest_zone":   raw_dst,
                            "canonical_zone":  canonical,
                            "rule_index":      rule.rule_index,
                        },
                        remediation=(
                            f"Restrict the rule so that '{raw_src}' cannot reach '{raw_dst}'. "
                            f"Split into per-sub-zone rules that only allow same-zone traffic, "
                            f"or remove the conflicting zone entries from this rule."
                        ),
                    ))

    logger.info(f"Intra-zone lateral movement check: {len(findings)} findings")
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
