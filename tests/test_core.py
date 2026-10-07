"""
tests/test_core.py

Test suite for backend/ai_explainer.py:
- Score is deterministic and identical across 100 calls
- Fake log_id 'L-99999' is rejected by evidence firewall
- Recommendation targeting '8.8.8.8' (not in chain entities) is rejected
- Template report always passes validation (citations_verified: True)
- Benign scenario does not crash
- Malformed inputs handled gracefully without raising exceptions
"""

import json
import sys
from pathlib import Path
import copy

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.ai_explainer import (
    WEIGHTS,
    compute_risk,
    severity_label,
    validate_citations,
    template_report,
)


def load_fixtures():
    with open(root_dir / "data" / "mock_chains.json", "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(root_dir / "data" / "mock_logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)
    with open(root_dir / "data" / "mock_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)
    return chains, logs, report


def test_score_identical_across_100_calls():
    """Verify compute_risk is completely deterministic across 100 invocations."""
    chains, logs, _ = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    first_score, first_rationale = compute_risk(c1_chain, logs)
    assert first_score == 100, f"C-1 expected capped score 100, got {first_score}"
    assert "5 linked attack stages" in first_rationale
    assert "data exfiltration" in first_rationale
    assert "privilege escalation" in first_rationale
    assert "lateral movement across hosts" in first_rationale

    for _ in range(100):
        score, rationale = compute_risk(c1_chain, logs)
        assert score == first_score, f"Inconsistent score: {score} != {first_score}"
        assert rationale == first_rationale, f"Inconsistent rationale: {rationale} != {first_rationale}"

    # Also verify severity label
    assert severity_label(first_score) == "high"
    assert severity_label(50) == "medium"
    assert severity_label(20) == "low"
    assert severity_label(0) == "low"

    print("  [PASS] test_score_identical_across_100_calls")


def test_fake_log_id_rejected():
    """Verify evidence firewall rejects a report containing a fabricated log_id 'L-99999'."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    # Baseline valid report passes
    assert validate_citations(report, c1_chain, logs) is True

    # Tamper with stage 1: inject non-existent log_id
    tampered_report = copy.deepcopy(report)
    tampered_report["stages"][0]["log_ids"].append("L-99999")

    is_valid = validate_citations(tampered_report, c1_chain, logs)
    assert is_valid is False, "Report with fake log_id 'L-99999' must be rejected"

    # Tamper with stage 1: replace legitimate log_id with fake log_id
    tampered_report2 = copy.deepcopy(report)
    tampered_report2["stages"][0]["log_ids"] = ["L-99999"]
    assert validate_citations(tampered_report2, c1_chain, logs) is False

    print("  [PASS] test_fake_log_id_rejected")


def test_recommendation_target_not_in_chain_rejected():
    """Verify evidence firewall rejects recommendation with target '8.8.8.8' not in chain entities."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    # Tamper recommendation target
    tampered_report = copy.deepcopy(report)
    tampered_report["recommendations"].append(
        {
            "action": "block_ip",
            "target": "8.8.8.8",
            "why": "Arbitrary external IP not in chain",
        }
    )

    is_valid = validate_citations(tampered_report, c1_chain, logs)
    assert is_valid is False, "Recommendation with target '8.8.8.8' not in chain must be rejected"

    # Also test disallowed action
    tampered_report_action = copy.deepcopy(report)
    tampered_report_action["recommendations"].append(
        {
            "action": "nuke_firewall",
            "target": "198.51.100.72",
            "why": "Disallowed action string",
        }
    )
    assert validate_citations(tampered_report_action, c1_chain, logs) is False

    print("  [PASS] test_recommendation_target_not_in_chain_rejected")


def test_template_report_always_passes_validation():
    """Verify rule-based template_report always produces a valid report with citations_verified=True."""
    chains, logs, _ = load_fixtures()

    for c in chains:
        chain_id = c["chain_id"]
        rep = template_report(c, logs)

        assert isinstance(rep, dict), f"template_report for {chain_id} must return dict"
        assert rep["risk_score"] >= 0
        assert len(rep["summary"]) > 0
        assert len(rep["stages"]) == len(c["stages"])
        assert rep["citations_verified"] is True, f"citations_verified must be True for {chain_id}"
        assert validate_citations(rep, c, logs) is True, f"validate_citations failed for template report {chain_id}"

        # Recommendations sanity
        for rec in rep["recommendations"]:
            assert rec["action"] in {"block_ip", "revoke_user_token", "isolate_host", "reset_credentials"}

    print("  [PASS] test_template_report_always_passes_validation")


def test_benign_scenario_does_not_crash():
    """Verify benign activity or empty chain scenario runs gracefully without crashing."""
    _, logs, _ = load_fixtures()
    benign_logs = [r for r in logs if r.get("chain_id") == "C-3"]

    benign_chain = {
        "chain_id": "C-3",
        "severity": "low",
        "start": "2026-10-07T09:00:00Z",
        "end": "2026-10-07T10:00:00Z",
        "entities": {"users": ["sarah.lee"], "ips": ["10.0.4.102"], "hosts": ["WS-HR-04"], "resources": []},
        "stages": [],
    }

    # 1. compute_risk
    score, rationale = compute_risk(benign_chain, benign_logs)
    assert score == 0, f"Benign chain score should be 0, got {score}"
    assert "0 linked attack stages" in rationale
    assert severity_label(score) == "low"

    # 2. template_report
    rep = template_report(benign_chain, benign_logs)
    assert isinstance(rep, dict)
    assert rep["risk_score"] == 0
    assert len(rep["stages"]) == 0
    assert rep["citations_verified"] is True

    # 3. Empty chain dict
    score_empty, _ = compute_risk({}, [])
    assert score_empty == 0
    rep_empty = template_report({}, [])
    assert isinstance(rep_empty, dict)

    # 4. Malformed inputs to validate_citations must return False, never raise
    assert validate_citations(None, {}, []) is False
    assert validate_citations({}, None, []) is False
    assert validate_citations({}, {}, None) is False
    assert validate_citations("invalid", 123, [None]) is False
    assert validate_citations({"stages": [{"stage_no": 99}]}, {"stages": []}, []) is False

    print("  [PASS] test_benign_scenario_does_not_crash")


def test_wrong_type_target_rejected():
    """Verify evidence firewall rejects recommendations where target does not match action type."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    # Baseline valid report
    assert validate_citations(report, c1_chain, logs) is True

    # 1. block_ip on a user (dchen is a user, not an IP)
    tampered_user_block = copy.deepcopy(report)
    tampered_user_block["recommendations"] = [
        {"action": "block_ip", "target": "dchen", "why": "Invalid target type for block_ip"}
    ]
    assert validate_citations(tampered_user_block, c1_chain, logs) is False, (
        "block_ip targeting a user must be rejected"
    )

    # 2. revoke_user_token on an IP
    tampered_ip_revoke = copy.deepcopy(report)
    tampered_ip_revoke["recommendations"] = [
        {"action": "revoke_user_token", "target": "198.51.100.72", "why": "Invalid target type for revoke_user_token"}
    ]
    assert validate_citations(tampered_ip_revoke, c1_chain, logs) is False, (
        "revoke_user_token targeting an IP must be rejected"
    )

    # 3. isolate_host on a user
    tampered_host_isolate = copy.deepcopy(report)
    tampered_host_isolate["recommendations"] = [
        {"action": "isolate_host", "target": "dchen", "why": "Invalid target type for isolate_host"}
    ]
    assert validate_citations(tampered_host_isolate, c1_chain, logs) is False, (
        "isolate_host targeting a user must be rejected"
    )

    # 4. reset_credentials on a host
    tampered_host_cred = copy.deepcopy(report)
    tampered_host_cred["recommendations"] = [
        {"action": "reset_credentials", "target": "WS-DEV-01", "why": "Invalid target type for reset_credentials"}
    ]
    assert validate_citations(tampered_host_cred, c1_chain, logs) is False, (
        "reset_credentials targeting a host must be rejected"
    )

    print("  [PASS] test_wrong_type_target_rejected")


def test_fake_timestamp_rejected():
    """Verify evidence firewall rejects reports where a stage timestamp does not match cited log row."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    # 1. Hallucinated timestamp format
    tampered_fake_ts = copy.deepcopy(report)
    tampered_fake_ts["stages"][0]["timestamps"] = ["2026-10-07T99:99:99Z"]
    assert validate_citations(tampered_fake_ts, c1_chain, logs) is False, (
        "Fake timestamp '2026-10-07T99:99:99Z' must be rejected"
    )

    # 2. Off-by-one second timestamp (not equal to str(timestamp) of cited log row)
    tampered_off_by_one = copy.deepcopy(report)
    tampered_off_by_one["stages"][0]["timestamps"] = ["2026-10-07T10:01:16Z"]  # Actual is 10:01:15Z
    assert validate_citations(tampered_off_by_one, c1_chain, logs) is False, (
        "Off-by-one timestamp must be strictly rejected"
    )

    # 3. Non-string timestamp
    tampered_non_str = copy.deepcopy(report)
    tampered_non_str["stages"][0]["timestamps"] = [1791367275]
    assert validate_citations(tampered_non_str, c1_chain, logs) is False, (
        "Non-string timestamp must be rejected"
    )

    print("  [PASS] test_fake_timestamp_rejected")


def main():
    print("[*] Running test suite for backend/ai_explainer.py...")
    test_score_identical_across_100_calls()
    test_fake_log_id_rejected()
    test_recommendation_target_not_in_chain_rejected()
    test_template_report_always_passes_validation()
    test_benign_scenario_does_not_crash()
    test_wrong_type_target_rejected()
    test_fake_timestamp_rejected()
    print("\n[SUCCESS] All core tests passed successfully!")


if __name__ == "__main__":
    main()
