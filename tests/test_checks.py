"""
Unit tests for app/validation/checks.py
Covers all four check functions with positive, negative, and edge-case scenarios.
"""

import pytest
from app.models import PolicyRule, FirewallRule, Finding
from app.validation.checks import (
    check_unauthorized_flows,
    check_condition_violations,
    check_missing_implementations,
    check_hygiene,
)


# ─────────────────────────────────────────────────────────────
# Fixtures / helpers
# ─────────────────────────────────────────────────────────────

def make_policy(
    source_zone="trust",
    dest_zone="untrust",
    allowed_ports=None,
    allowed_applications=None,
    required_profiles=None,
    logging_required=True,
    action="allow",
    deny_severity=None,
):
    return PolicyRule(
        source_zone=source_zone,
        dest_zone=dest_zone,
        allowed_ports=allowed_ports or {"443", "80"},
        allowed_applications=allowed_applications or {"ssl"},
        required_profiles=required_profiles if required_profiles is not None else {},
        logging_required=logging_required,
        action=action,
        deny_severity=deny_severity,
    )


def make_fw_rule(
    rule_name="test-rule",
    source_zones=None,
    dest_zones=None,
    services=None,
    applications=None,
    action="allow",
    av_profile=None,
    url_profile=None,
    security_profile_group=None,
    log_forwarding=None,
    log_at_session_end=True,
    enabled=True,
    rule_index=0,
):
    return FirewallRule(
        rule_name=rule_name,
        source_zones=source_zones or {"trust"},
        dest_zones=dest_zones or {"untrust"},
        source_addresses={"any"},
        dest_addresses={"any"},
        applications=applications or {"ssl"},
        services=services or {"443"},
        action=action,
        security_profile_group=security_profile_group,
        av_profile=av_profile,
        url_profile=url_profile,
        log_forwarding=log_forwarding,
        log_at_session_end=log_at_session_end,
        enabled=enabled,
        rule_index=rule_index,
    )


# ─────────────────────────────────────────────────────────────
# CHECK 1: UNAUTHORIZED FLOW
# ─────────────────────────────────────────────────────────────

class TestCheckUnauthorizedFlows:

    def test_no_finding_when_zone_pair_in_matrix(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"untrust"})
        findings = check_unauthorized_flows([fw_rule], [policy])
        assert findings == []

    def test_finding_when_zone_pair_not_in_matrix(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(
            rule_name="rogue-rule",
            source_zones={"dmz"},
            dest_zones={"internal"},
        )
        findings = check_unauthorized_flows([fw_rule], [policy])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == "UNAUTHORIZED_FLOW"
        assert f.severity == Finding.SEVERITY_CRITICAL
        assert f.rule_name == "rogue-rule"

    def test_no_finding_for_disabled_rule(self):
        # Disabled rules are skipped — they can't carry unauthorized traffic
        fw_rule = make_fw_rule(enabled=False, source_zones={"dmz"}, dest_zones={"internal"})
        findings = check_unauthorized_flows([fw_rule], [])
        assert findings == []

    def test_no_finding_for_deny_rule_with_no_matrix_entry(self):
        # Deny rules for unlisted flows are expected and should not be flagged
        fw_rule = make_fw_rule(action="deny", source_zones={"dmz"}, dest_zones={"internal"})
        findings = check_unauthorized_flows([fw_rule], [])
        assert findings == []

    def test_fw_rule_with_any_source_zone_matches_policy(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"any"}, dest_zones={"untrust"})
        findings = check_unauthorized_flows([fw_rule], [policy])
        assert findings == []

    def test_fw_rule_with_any_dest_zone_matches_policy(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"any"})
        findings = check_unauthorized_flows([fw_rule], [policy])
        assert findings == []

    def test_multiple_rules_only_unmatched_flagged(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        good_rule = make_fw_rule(rule_name="good", source_zones={"trust"}, dest_zones={"untrust"})
        bad_rule  = make_fw_rule(rule_name="bad",  source_zones={"dmz"},   dest_zones={"internal"})
        findings = check_unauthorized_flows([good_rule, bad_rule], [policy])
        assert len(findings) == 1
        assert findings[0].rule_name == "bad"

    def test_empty_inputs_produce_no_findings(self):
        assert check_unauthorized_flows([], []) == []


# ─────────────────────────────────────────────────────────────
# CHECK 2: CONDITION VIOLATIONS
# ─────────────────────────────────────────────────────────────

class TestCheckConditionViolations:

    def test_no_finding_when_fully_compliant(self):
        policy = make_policy(
            allowed_ports={"443"},
            required_profiles={"av": "strict"},
            logging_required=True,
        )
        fw_rule = make_fw_rule(
            services={"443"},
            av_profile="strict",
            log_at_session_end=True,
        )
        findings = check_condition_violations([fw_rule], [policy])
        assert findings == []

    def test_port_violation_flagged(self):
        policy = make_policy(allowed_ports={"443"})
        fw_rule = make_fw_rule(services={"443", "8080", "22"})
        findings = check_condition_violations([fw_rule], [policy])
        port_findings = [f for f in findings if f.finding_type == "CONDITION_VIOLATION"
                         and "8080" in str(f.details.get("disallowed_services", ""))
                            or "22" in str(f.details.get("disallowed_services", ""))]
        assert any("services" in f.description or "8080" in f.description or "22" in f.description
                   for f in findings)
        assert all(f.severity == Finding.SEVERITY_HIGH
                   for f in findings if "disallowed_services" in f.details)

    def test_any_in_allowed_ports_skips_port_check(self):
        policy = make_policy(allowed_ports={"any"})
        fw_rule = make_fw_rule(services={"443", "8080", "22", "3389"})
        findings = check_condition_violations([fw_rule], [policy])
        port_findings = [f for f in findings if "disallowed_services" in f.details]
        assert port_findings == []

    def test_app_default_not_flagged_as_port_violation(self):
        policy = make_policy(allowed_ports={"443"})
        fw_rule = make_fw_rule(services={"443", "app-default"})
        findings = check_condition_violations([fw_rule], [policy])
        port_findings = [f for f in findings if "disallowed_services" in f.details]
        assert port_findings == []

    def test_missing_logging_flagged(self):
        policy = make_policy(logging_required=True)
        fw_rule = make_fw_rule(log_at_session_end=False, log_forwarding=None)
        findings = check_condition_violations([fw_rule], [policy])
        log_findings = [f for f in findings if "logging" in f.description.lower()]
        assert len(log_findings) == 1
        assert log_findings[0].severity == Finding.SEVERITY_MEDIUM

    def test_log_forwarding_satisfies_logging_requirement(self):
        policy = make_policy(logging_required=True)
        fw_rule = make_fw_rule(log_at_session_end=False, log_forwarding="splunk-profile")
        findings = check_condition_violations([fw_rule], [policy])
        log_findings = [f for f in findings if "logging" in f.description.lower()]
        assert log_findings == []

    def test_logging_not_required_no_finding(self):
        policy = make_policy(logging_required=False)
        fw_rule = make_fw_rule(log_at_session_end=False, log_forwarding=None)
        findings = check_condition_violations([fw_rule], [policy])
        log_findings = [f for f in findings if "logging" in f.description.lower()]
        assert log_findings == []

    def test_missing_av_profile_flagged(self):
        policy = make_policy(required_profiles={"av": "strict"})
        fw_rule = make_fw_rule(av_profile=None, security_profile_group=None)
        findings = check_condition_violations([fw_rule], [policy])
        av_findings = [f for f in findings if "AV" in f.description]
        assert len(av_findings) == 1
        assert av_findings[0].severity == Finding.SEVERITY_HIGH

    def test_security_profile_group_satisfies_av_requirement(self):
        policy = make_policy(required_profiles={"av": "strict"})
        fw_rule = make_fw_rule(av_profile=None, security_profile_group="default-group")
        findings = check_condition_violations([fw_rule], [policy])
        av_findings = [f for f in findings if "AV" in f.description]
        assert av_findings == []

    def test_missing_url_profile_flagged(self):
        policy = make_policy(required_profiles={"url": "default"})
        fw_rule = make_fw_rule(url_profile=None, security_profile_group=None)
        findings = check_condition_violations([fw_rule], [policy])
        url_findings = [f for f in findings if "URL" in f.description]
        assert len(url_findings) == 1
        assert url_findings[0].severity == Finding.SEVERITY_HIGH

    def test_action_mismatch_flagged_as_critical(self):
        # deny policy with no deny_severity → falls back to CRITICAL
        policy = make_policy(action="deny")
        fw_rule = make_fw_rule(action="allow")
        findings = check_condition_violations([fw_rule], [policy])
        action_findings = [f for f in findings if "action" in f.description.lower()]
        assert len(action_findings) == 1
        assert action_findings[0].severity == Finding.SEVERITY_CRITICAL

    def test_shall_not_be_allowed_violation_flagged_as_critical(self):
        # "Shall not be allowed" → deny_severity=CRITICAL
        policy = make_policy(action="deny", deny_severity=Finding.SEVERITY_CRITICAL)
        fw_rule = make_fw_rule(action="allow")
        findings = check_condition_violations([fw_rule], [policy])
        action_findings = [f for f in findings if "action" in f.description.lower()]
        assert len(action_findings) == 1
        assert action_findings[0].severity == Finding.SEVERITY_CRITICAL

    def test_should_not_be_allowed_violation_flagged_as_high(self):
        # "Should not be allowed" → deny_severity=HIGH (conditional prohibition)
        policy = make_policy(action="deny", deny_severity=Finding.SEVERITY_HIGH)
        fw_rule = make_fw_rule(action="allow")
        findings = check_condition_violations([fw_rule], [policy])
        action_findings = [f for f in findings if "action" in f.description.lower()]
        assert len(action_findings) == 1
        assert action_findings[0].severity == Finding.SEVERITY_HIGH

    def test_deny_fw_rule_skipped_in_condition_check(self):
        # FW rules with action=deny are discarded — no findings even with policy violations
        policy = make_policy(action="allow", logging_required=True,
                             required_profiles={"av": "strict"})
        fw_rule = make_fw_rule(action="deny", log_at_session_end=False,
                               av_profile=None, security_profile_group=None)
        findings = check_condition_violations([fw_rule], [policy])
        assert findings == []

    def test_disabled_rule_skipped(self):
        policy = make_policy(logging_required=True, required_profiles={"av": "strict"})
        fw_rule = make_fw_rule(
            enabled=False,
            log_at_session_end=False,
            av_profile=None,
            security_profile_group=None,
        )
        findings = check_condition_violations([fw_rule], [policy])
        assert findings == []

    def test_no_matching_policy_skipped(self):
        policy = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"dmz"}, dest_zones={"internal"})
        findings = check_condition_violations([fw_rule], [policy])
        assert findings == []


# ─────────────────────────────────────────────────────────────
# CHECK 3: MISSING IMPLEMENTATION
# ─────────────────────────────────────────────────────────────

class TestCheckMissingImplementations:

    def test_no_finding_when_flow_is_covered(self):
        policy  = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"untrust"}, enabled=True)
        findings = check_missing_implementations([fw_rule], [policy])
        assert findings == []

    def test_finding_when_no_firewall_rule_covers_policy(self):
        policy = make_policy(source_zone="trust", dest_zone="dmz")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"untrust"})
        findings = check_missing_implementations([fw_rule], [policy])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == "MISSING_IMPLEMENTATION"
        assert f.severity == Finding.SEVERITY_MEDIUM
        assert f.rule_name is None
        assert "trust" in f.description
        assert "dmz" in f.description

    def test_disabled_rule_does_not_satisfy_policy(self):
        policy  = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"untrust"}, enabled=False)
        findings = check_missing_implementations([fw_rule], [policy])
        assert len(findings) == 1

    def test_deny_policy_not_checked(self):
        # Deny matrix entries don't need a firewall rule implementation
        policy = make_policy(action="deny")
        findings = check_missing_implementations([], [policy])
        assert findings == []

    def test_fw_rule_with_any_zones_covers_policy(self):
        policy  = make_policy(source_zone="trust", dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"any"}, dest_zones={"any"})
        findings = check_missing_implementations([fw_rule], [policy])
        assert findings == []

    def test_multiple_policies_each_checked_independently(self):
        p1 = make_policy(source_zone="trust",  dest_zone="untrust")
        p2 = make_policy(source_zone="dmz",    dest_zone="untrust")
        fw_rule = make_fw_rule(source_zones={"trust"}, dest_zones={"untrust"})
        findings = check_missing_implementations([fw_rule], [p1, p2])
        # p1 is covered, p2 is not
        assert len(findings) == 1
        assert "dmz" in findings[0].description

    def test_empty_inputs_produce_no_findings(self):
        assert check_missing_implementations([], []) == []


# ─────────────────────────────────────────────────────────────
# CHECK 4: HYGIENE
# ─────────────────────────────────────────────────────────────

class TestCheckHygiene:

    def test_no_finding_for_clean_rule(self):
        fw_rule = make_fw_rule(
            enabled=True,
            action="allow",
            source_zones={"trust"},
            dest_zones={"untrust"},
            services={"443"},
        )
        findings = check_hygiene([fw_rule])
        assert findings == []

    def test_disabled_rule_flagged_as_low(self):
        fw_rule = make_fw_rule(rule_name="stale-rule", enabled=False)
        findings = check_hygiene([fw_rule])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == "HYGIENE_DISABLED_RULE"
        assert f.severity == Finding.SEVERITY_LOW
        assert f.rule_name == "stale-rule"

    def test_any_any_permit_flagged_as_critical(self):
        fw_rule = make_fw_rule(
            rule_name="allow-all",
            source_zones={"any"},
            dest_zones={"any"},
            services={"any"},
            action="allow",
        )
        findings = check_hygiene([fw_rule])
        any_any = [f for f in findings if f.finding_type == "HYGIENE_ANY_ANY_PERMIT"]
        assert len(any_any) == 1
        assert any_any[0].severity == Finding.SEVERITY_CRITICAL

    def test_any_any_deny_not_flagged(self):
        fw_rule = make_fw_rule(
            source_zones={"any"}, dest_zones={"any"}, services={"any"}, action="deny"
        )
        findings = check_hygiene([fw_rule])
        assert not any(f.finding_type == "HYGIENE_ANY_ANY_PERMIT" for f in findings)

    def test_shadowed_rule_flagged(self):
        # Rule A: any→any allow all services — broad
        broad = make_fw_rule(
            rule_name="broad-rule",
            source_zones={"any"},
            dest_zones={"any"},
            services={"any"},
            applications={"any"},
            action="allow",
            rule_index=0,
        )
        # Rule B: trust→untrust allow 443 — fully covered by A
        specific = make_fw_rule(
            rule_name="specific-rule",
            source_zones={"trust"},
            dest_zones={"untrust"},
            services={"443"},
            applications={"ssl"},
            action="allow",
            rule_index=1,
        )
        findings = check_hygiene([broad, specific])
        shadow_findings = [f for f in findings if f.finding_type == "HYGIENE_SHADOWED_RULE"]
        assert len(shadow_findings) == 1
        f = shadow_findings[0]
        assert f.rule_name == "specific-rule"
        assert f.details["shadowed_by"] == "broad-rule"
        assert f.severity == Finding.SEVERITY_LOW

    def test_no_shadow_when_order_reversed(self):
        # Specific rule first — broad rule later — no shadow
        specific = make_fw_rule(
            rule_name="specific-rule",
            source_zones={"trust"},
            dest_zones={"untrust"},
            services={"443"},
            applications={"ssl"},
            action="allow",
            rule_index=0,
        )
        broad = make_fw_rule(
            rule_name="broad-rule",
            source_zones={"any"},
            dest_zones={"any"},
            services={"any"},
            applications={"any"},
            action="allow",
            rule_index=1,
        )
        findings = check_hygiene([specific, broad])
        shadow_findings = [f for f in findings if f.finding_type == "HYGIENE_SHADOWED_RULE"]
        assert shadow_findings == []

    def test_partial_overlap_not_shadowed(self):
        # Broad covers source, but different dest zone — not a full shadow
        rule_a = make_fw_rule(
            rule_name="rule-a",
            source_zones={"any"},
            dest_zones={"untrust"},
            services={"any"},
            applications={"any"},
            action="allow",
            rule_index=0,
        )
        rule_b = make_fw_rule(
            rule_name="rule-b",
            source_zones={"trust"},
            dest_zones={"dmz"},   # different dest — not covered by rule_a
            services={"443"},
            applications={"ssl"},
            action="allow",
            rule_index=1,
        )
        findings = check_hygiene([rule_a, rule_b])
        shadow_findings = [f for f in findings if f.finding_type == "HYGIENE_SHADOWED_RULE"]
        assert shadow_findings == []

    def test_disabled_rule_not_considered_for_shadowing(self):
        # A disabled broad rule should not shadow rules below it
        disabled_broad = make_fw_rule(
            rule_name="disabled-broad",
            source_zones={"any"}, dest_zones={"any"}, services={"any"},
            applications={"any"}, action="allow", enabled=False, rule_index=0,
        )
        specific = make_fw_rule(
            rule_name="specific",
            source_zones={"trust"}, dest_zones={"untrust"}, services={"443"},
            applications={"ssl"}, action="allow", enabled=True, rule_index=1,
        )
        findings = check_hygiene([disabled_broad, specific])
        shadow_findings = [f for f in findings if f.finding_type == "HYGIENE_SHADOWED_RULE"]
        assert shadow_findings == []

    def test_only_first_shadowing_rule_reported(self):
        # Rule C is shadowed by both A and B — only A (the first) should be reported
        rule_a = make_fw_rule(
            rule_name="rule-a", source_zones={"any"}, dest_zones={"any"},
            services={"any"}, applications={"any"}, action="allow", rule_index=0,
        )
        rule_b = make_fw_rule(
            rule_name="rule-b", source_zones={"any"}, dest_zones={"any"},
            services={"any"}, applications={"any"}, action="allow", rule_index=1,
        )
        rule_c = make_fw_rule(
            rule_name="rule-c", source_zones={"trust"}, dest_zones={"untrust"},
            services={"443"}, applications={"ssl"}, action="allow", rule_index=2,
        )
        findings = check_hygiene([rule_a, rule_b, rule_c])
        shadow_findings = [f for f in findings if f.finding_type == "HYGIENE_SHADOWED_RULE"
                           and f.rule_name == "rule-c"]
        assert len(shadow_findings) == 1
        assert shadow_findings[0].details["shadowed_by"] == "rule-a"
