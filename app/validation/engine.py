"""
Validation Engine
Orchestrates all checks, scores findings, and returns a structured AuditResult.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict

from app.models import PolicyRule, FirewallRule, Finding
from app.validation.checks import (
    check_unauthorized_flows,
    check_condition_violations,
    check_missing_implementations,
    check_hygiene,
)

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    Finding.SEVERITY_CRITICAL: 10,
    Finding.SEVERITY_HIGH:     5,
    Finding.SEVERITY_MEDIUM:   2,
    Finding.SEVERITY_LOW:      1,
}


@dataclass
class AuditResult:
    total_firewall_rules: int
    total_policy_rules: int
    findings: List[Finding]
    compliance_score: float           # 0–100
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_type: Dict[str, int]    = field(default_factory=dict)
    summary: str = ""


def run_audit(
    policy_rules: List[PolicyRule],
    firewall_rules: List[FirewallRule],
) -> AuditResult:
    """
    Run all validation checks and return a scored AuditResult.

    Args:
        policy_rules:   Normalized list of PolicyRule from the matrix
        firewall_rules: Normalized list of FirewallRule from the rulebase

    Returns:
        AuditResult with all findings and compliance score
    """
    logger.info(
        f"Starting audit: {len(policy_rules)} policy rules, "
        f"{len(firewall_rules)} firewall rules"
    )

    all_findings: List[Finding] = []

    all_findings.extend(check_unauthorized_flows(firewall_rules, policy_rules))
    all_findings.extend(check_condition_violations(firewall_rules, policy_rules))
    all_findings.extend(check_missing_implementations(firewall_rules, policy_rules))
    all_findings.extend(check_hygiene(firewall_rules))

    score = _calculate_score(all_findings, firewall_rules)

    by_severity = {s: 0 for s in SEVERITY_WEIGHTS}
    by_type: Dict[str, int] = {}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1

    summary = _generate_summary(score, by_severity, len(firewall_rules), len(policy_rules))

    result = AuditResult(
        total_firewall_rules=len(firewall_rules),
        total_policy_rules=len(policy_rules),
        findings=all_findings,
        compliance_score=score,
        findings_by_severity=by_severity,
        findings_by_type=by_type,
        summary=summary,
    )

    logger.info(
        f"Audit complete: score={score:.1f}%, "
        f"critical={by_severity['CRITICAL']}, high={by_severity['HIGH']}, "
        f"medium={by_severity['MEDIUM']}, low={by_severity['LOW']}"
    )
    return result


def _calculate_score(findings: List[Finding], firewall_rules: List[FirewallRule]) -> float:
    """
    Compliance score: starts at 100, deducted per finding weighted by severity.
    Score is per-rule, so large rulebases don't get unfairly penalized.
    """
    if not firewall_rules:
        return 0.0

    max_possible_penalty = len(firewall_rules) * SEVERITY_WEIGHTS[Finding.SEVERITY_CRITICAL]
    actual_penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Cap at 0
    score = max(0.0, 100.0 * (1 - actual_penalty / max_possible_penalty))
    return round(score, 1)


def _generate_summary(
    score: float,
    by_severity: Dict[str, int],
    total_fw_rules: int,
    total_policy_rules: int,
) -> str:
    if score >= 90:
        rating = "COMPLIANT"
    elif score >= 70:
        rating = "PARTIALLY COMPLIANT"
    else:
        rating = "NON-COMPLIANT"

    return (
        f"Audit Rating: {rating} | Score: {score}% | "
        f"Firewall Rules: {total_fw_rules} | Matrix Entries: {total_policy_rules} | "
        f"Critical: {by_severity.get('CRITICAL', 0)}, "
        f"High: {by_severity.get('HIGH', 0)}, "
        f"Medium: {by_severity.get('MEDIUM', 0)}, "
        f"Low: {by_severity.get('LOW', 0)}"
    )
