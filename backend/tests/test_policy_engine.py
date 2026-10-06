"""Unit tests for the policy decision logic.

No database, no HTTP: the engine is pure, so the rules that decide access can
be tested exhaustively and quickly.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from zta.policy import AccessContext, DevicePosture, PolicySpec, evaluate, trust_score
from zta.policy.engine import unmet_conditions

MANAGED = DevicePosture(
    device_id="laptop-1", registered=True, disk_encrypted=True, screen_lock=True,
    os_up_to_date=True, endpoint_protection=True,
)


def context(**overrides) -> AccessContext:
    base = {
        "method": "GET",
        "path": "/reports/q1",
        "resource": "reports",
        "authenticated": True,
        "username": "employee",
        "role": "EMPLOYEE",
        "source_ip": "10.0.0.5",
        "posture": MANAGED,
        "trust_score": 90,
        "timestamp": datetime(2026, 3, 4, 10, 0, tzinfo=timezone.utc),   # a Wednesday
    }
    base.update(overrides)
    return AccessContext(**base)


ALLOW_REPORTS = PolicySpec(
    name="allow-employee-reports", effect="ALLOW", priority=20,
    roles=("EMPLOYEE", "ADMIN"), resources=("reports",),
    require_registered_device=True, min_trust_score=60,
)


# --- the default ---------------------------------------------------------
def test_unauthenticated_is_denied_before_any_policy_runs():
    result = evaluate(context(authenticated=False), [ALLOW_REPORTS])
    assert result.decision == "DENY"
    assert "Unauthenticated" in result.reason


def test_no_policies_means_deny():
    result = evaluate(context(), [])
    assert result.decision == "DENY"
    assert "No policy grants" in result.reason


def test_matching_policy_allows_and_names_itself():
    result = evaluate(context(), [ALLOW_REPORTS])
    assert result.allowed
    assert result.matched_policy == "allow-employee-reports"
    assert result.policy_version == 1


def test_disabled_policies_are_skipped():
    disabled = PolicySpec(**{**ALLOW_REPORTS.__dict__, "enabled": False})
    assert evaluate(context(), [disabled]).decision == "DENY"


# --- ordering ------------------------------------------------------------
def test_lower_priority_number_wins():
    deny_first = PolicySpec(name="deny-all-reports", effect="DENY", priority=5, resources=("reports",))
    result = evaluate(context(), [ALLOW_REPORTS, deny_first])
    assert result.decision == "DENY"
    assert result.matched_policy == "deny-all-reports"


def test_first_match_wins_even_if_a_later_policy_would_deny():
    late_deny = PolicySpec(name="zz-deny", effect="DENY", priority=99, resources=("reports",))
    result = evaluate(context(), [ALLOW_REPORTS, late_deny])
    assert result.allowed and result.matched_policy == "allow-employee-reports"


def test_equal_priority_is_broken_by_name_deterministically():
    a = PolicySpec(name="aaa-allow", effect="ALLOW", priority=10, resources=("reports",))
    b = PolicySpec(name="bbb-deny", effect="DENY", priority=10, resources=("reports",))
    assert evaluate(context(), [b, a]).matched_policy == "aaa-allow"


# --- individual conditions ----------------------------------------------
def test_role_condition():
    assert evaluate(context(role="GUEST"), [ALLOW_REPORTS]).decision == "DENY"


def test_resource_condition():
    assert evaluate(context(resource="admin", path="/admin/users"), [ALLOW_REPORTS]).decision == "DENY"


def test_method_condition():
    read_only = PolicySpec(name="read-only", effect="ALLOW", resources=("reports",), methods=("GET",))
    assert evaluate(context(), [read_only]).allowed
    assert evaluate(context(method="DELETE"), [read_only]).decision == "DENY"


def test_path_glob_condition():
    policy = PolicySpec(name="q1-only", effect="ALLOW", resources=("reports",), path_globs=("/reports/q1*",))
    assert evaluate(context(path="/reports/q1"), [policy]).allowed
    assert evaluate(context(path="/reports/q2"), [policy]).decision == "DENY"


def test_source_cidr_condition():
    policy = PolicySpec(name="corp-only", effect="ALLOW", resources=("reports",), source_cidrs=("10.0.0.0/8",))
    assert evaluate(context(source_ip="10.0.0.5"), [policy]).allowed
    assert evaluate(context(source_ip="203.0.113.9"), [policy]).decision == "DENY"


def test_malformed_source_ip_never_matches_a_network_condition():
    policy = PolicySpec(name="corp-only", effect="ALLOW", resources=("reports",), source_cidrs=("10.0.0.0/8",))
    assert evaluate(context(source_ip="not-an-ip"), [policy]).decision == "DENY"


def test_registered_device_condition():
    assert evaluate(context(posture=DevicePosture(registered=False)), [ALLOW_REPORTS]).decision == "DENY"


def test_quarantined_device_fails_the_registration_condition():
    quarantined = DevicePosture(device_id="laptop-1", registered=True, quarantined=True)
    assert evaluate(context(posture=quarantined), [ALLOW_REPORTS]).decision == "DENY"


def test_mfa_condition():
    policy = PolicySpec(name="mfa", effect="ALLOW", resources=("reports",), require_mfa=True)
    assert evaluate(context(mfa_satisfied=False), [policy]).decision == "DENY"
    assert evaluate(context(mfa_satisfied=True), [policy]).allowed


def test_trust_score_condition():
    assert evaluate(context(trust_score=59), [ALLOW_REPORTS]).decision == "DENY"
    assert evaluate(context(trust_score=60), [ALLOW_REPORTS]).allowed


# --- time windows --------------------------------------------------------
@pytest.mark.parametrize(
    "hour,expected",
    [(8, False), (9, True), (12, True), (16, True), (17, False), (23, False)],
)
def test_business_hours_window(hour, expected):
    policy = PolicySpec(
        name="business-hours", effect="ALLOW", resources=("reports",),
        time_start_hour=9, time_end_hour=17,
    )
    moment = datetime(2026, 3, 4, hour, 0, tzinfo=timezone.utc)
    assert evaluate(context(timestamp=moment), [policy]).allowed is expected


@pytest.mark.parametrize("hour,expected", [(21, False), (22, True), (2, True), (6, False)])
def test_window_wrapping_midnight(hour, expected):
    policy = PolicySpec(
        name="overnight", effect="ALLOW", resources=("reports",), time_start_hour=22, time_end_hour=6
    )
    moment = datetime(2026, 3, 4, hour, 0, tzinfo=timezone.utc)
    assert evaluate(context(timestamp=moment), [policy]).allowed is expected


def test_weekday_condition():
    weekend_deny = PolicySpec(
        name="no-weekends", effect="DENY", priority=1, resources=("reports",), weekdays=(5, 6)
    )
    saturday = datetime(2026, 3, 7, 12, 0, tzinfo=timezone.utc)
    wednesday = datetime(2026, 3, 4, 12, 0, tzinfo=timezone.utc)
    assert evaluate(context(timestamp=saturday), [ALLOW_REPORTS, weekend_deny]).decision == "DENY"
    assert evaluate(context(timestamp=wednesday), [ALLOW_REPORTS, weekend_deny]).allowed


# --- explanations --------------------------------------------------------
def test_denial_explains_which_condition_failed():
    result = evaluate(context(mfa_satisfied=False, trust_score=90), [
        PolicySpec(name="admin-console", effect="ALLOW", resources=("reports",),
                   roles=("EMPLOYEE",), require_mfa=True)
    ])
    assert result.decision == "DENY"
    assert "MFA" in result.reason


def test_unmet_conditions_lists_every_failure():
    strict = PolicySpec(
        name="strict", effect="ALLOW", roles=("ADMIN",), resources=("reports",),
        require_mfa=True, min_trust_score=95,
    )
    unmet = unmet_conditions(strict, context(trust_score=50))
    assert set(unmet) == {"role", "MFA", "trust score"}


# --- trust scoring -------------------------------------------------------
def test_unauthenticated_has_no_trust():
    assert trust_score(authenticated=False, posture=MANAGED, mfa_satisfied=True) == 0


def test_managed_device_and_mfa_score_higher_than_password_alone():
    password_only = trust_score(authenticated=True)
    with_device = trust_score(authenticated=True, posture=MANAGED)
    with_both = trust_score(authenticated=True, posture=MANAGED, mfa_satisfied=True)
    assert password_only < with_device < with_both


def test_quarantined_device_destroys_trust():
    quarantined = DevicePosture(device_id="d", registered=True, quarantined=True)
    assert trust_score(authenticated=True, posture=quarantined, mfa_satisfied=True) < 50


def test_known_network_is_a_bonus_not_a_grant():
    off_network = trust_score(authenticated=True, posture=MANAGED, source_ip="203.0.113.9",
                              known_networks=["10.0.0.0/8"])
    on_network = trust_score(authenticated=True, posture=MANAGED, source_ip="10.0.0.5",
                             known_networks=["10.0.0.0/8"])
    assert on_network == off_network + 10


def test_score_is_bounded():
    everything = trust_score(authenticated=True, mfa_satisfied=True, posture=MANAGED,
                             source_ip="10.0.0.5", known_networks=["10.0.0.0/8"])
    assert 0 <= everything <= 100
