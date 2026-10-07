#!/usr/bin/env python3
"""
tests/check_mocks.py

Validates repository hygiene, mock data contracts, and cross-reference integrity
across mock_logs.json, mock_chains.json, mock_graph.json, and mock_report.json.
"""

import json
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def validate_citations(report, chain, logs):
    """Member 2 specification validation function."""
    valid_ids = {l["log_id"] for l in logs}
    cited = {i for s in report["stages"] for i in s["log_ids"]}
    every_stage_cited = all(s["log_ids"] for s in report["stages"])
    stages_match = len(report["stages"]) == len(chain["stages"])
    return cited <= valid_ids and every_stage_cited and stages_match


def main():
    root = Path(__file__).resolve().parent.parent
    print(f"[*] Validating repository at: {root}")

    # ---------------------------------------------------------
    # 1. Repo Hygiene Checks
    # ---------------------------------------------------------
    print("[1/5] Checking repository hygiene...")
    gitignore_path = root / ".gitignore"
    assert gitignore_path.exists(), ".gitignore is missing"
    gitignore_text = gitignore_path.read_text(encoding="utf-8")
    for req in [".env", "__pycache__", ".venv"]:
        assert req in gitignore_text, f".gitignore missing '{req}'"
    print("  [OK] .gitignore contains .env, __pycache__, .venv")

    env_example_path = root / ".env.example"
    assert env_example_path.exists(), ".env.example is missing"
    env_text = env_example_path.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=" in env_text, ".env.example missing 'OPENAI_API_KEY='"
    print("  [OK] .env.example contains OPENAI_API_KEY=")

    reqs_path = root / "requirements.txt"
    assert reqs_path.exists(), "requirements.txt is missing"
    reqs_text = reqs_path.read_text(encoding="utf-8").lower()
    for pkg in [
        "pandas",
        "networkx",
        "pyvis",
        "streamlit",
        "openai",
        "scikit-learn",
        "python-dotenv",
    ]:
        assert pkg in reqs_text, f"requirements.txt missing '{pkg}'"
    print("  [OK] requirements.txt contains all required dependencies")

    # ---------------------------------------------------------
    # 2. Validate mock_logs.json
    # ---------------------------------------------------------
    print("[2/5] Checking data/mock_logs.json...")
    logs_file = root / "data" / "mock_logs.json"
    assert logs_file.exists(), "data/mock_logs.json missing"
    with open(logs_file, "r", encoding="utf-8") as f:
        logs = json.load(f)

    assert isinstance(logs, list) and len(logs) > 0, "mock_logs.json must be a non-empty list"

    required_log_columns = {
        "log_id",
        "timestamp",
        "user",
        "src_ip",
        "host",
        "action",
        "resource",
        "source",
        "label",
    }
    all_log_ids = set()
    for row in logs:
        missing = required_log_columns - set(row.keys())
        assert not missing, f"Row {row.get('log_id')} missing columns: {missing}"
        assert row["log_id"] not in all_log_ids, f"Duplicate log_id: {row['log_id']}"
        all_log_ids.add(row["log_id"])

    # Scenario segregation
    c1_attack_logs = [r for r in logs if r.get("chain_id") == "C-1" and r.get("is_attack") is True]
    c1_bg_logs = [r for r in logs if r.get("chain_id") == "C-1" and r.get("is_attack") is False]
    c2_logs = [r for r in logs if r.get("chain_id") == "C-2"]
    c3_logs = [r for r in logs if r.get("chain_id") == "C-3"]

    # C-1 checks: 5 stages, 2 users, 2 IPs, 2 hosts
    assert len(c1_attack_logs) == 5, f"C-1 must have exactly 5 attack stages, found {len(c1_attack_logs)}"
    c1_users = {r["user"] for r in c1_attack_logs}
    c1_ips = {r["src_ip"] for r in c1_attack_logs}
    c1_hosts = {r["host"] for r in c1_attack_logs}
    assert len(c1_users) == 2, f"C-1 must involve exactly 2 users, found {c1_users}"
    assert len(c1_ips) == 2, f"C-1 must involve exactly 2 IPs, found {c1_ips}"
    assert len(c1_hosts) == 2, f"C-1 must involve exactly 2 hosts, found {c1_hosts}"
    print(f"  [OK] C-1 attack verified: 5 stages, 2 users {c1_users}, 2 IPs {c1_ips}, 2 hosts {c1_hosts}")

    # Background rows around C-1 (10-15 rows)
    assert 10 <= len(c1_bg_logs) <= 15, f"Expected 10-15 background rows around C-1, found {len(c1_bg_logs)}"
    print(f"  [OK] Background rows around C-1 verified: {len(c1_bg_logs)} rows for green neighbor nodes")

    # C-2 checks
    assert len(c2_logs) >= 3, f"C-2 must contain credential abuse logs, found {len(c2_logs)}"
    print(f"  [OK] C-2 scenario verified: {len(c2_logs)} log rows")

    # C-3 checks: benign activity, all benign
    assert len(c3_logs) >= 5, f"C-3 must contain benign logs, found {len(c3_logs)}"
    assert all(r["label"] == "benign" for r in c3_logs), "All C-3 logs must be labeled benign"
    print(f"  [OK] C-3 benign scenario verified: {len(c3_logs)} log rows")

    # ---------------------------------------------------------
    # 3. Validate mock_chains.json
    # ---------------------------------------------------------
    print("[3/5] Checking data/mock_chains.json...")
    chains_file = root / "data" / "mock_chains.json"
    assert chains_file.exists(), "data/mock_chains.json missing"
    with open(chains_file, "r", encoding="utf-8") as f:
        chains = json.load(f)

    assert isinstance(chains, list), "mock_chains.json must be a list of CHAIN dicts"
    chain_ids = [c["chain_id"] for c in chains]
    assert chain_ids == ["C-1", "C-2"], f"mock_chains.json must contain C-1 and C-2 only, found {chain_ids}"
    assert "C-3" not in chain_ids, "C-3 must NOT produce any chain in mock_chains.json"
    print("  [OK] mock_chains.json contains matching CHAIN dicts for C-1 and C-2 only")

    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    assert c1_chain["severity"] == "high", "C-1 severity must be high"
    assert len(c1_chain["stages"]) == 5, f"C-1 chain must have 5 stages, found {len(c1_chain['stages'])}"
    assert len(c1_chain["entities"]["users"]) == 2, "C-1 entities must list 2 users"
    assert len(c1_chain["entities"]["ips"]) == 2, "C-1 entities must list 2 IPs"
    assert len(c1_chain["entities"]["hosts"]) == 2, "C-1 entities must list 2 hosts"

    # Verify every log_id in chains exists in mock_logs.json
    for c in chains:
        for stage in c["stages"]:
            for lid in stage["log_ids"]:
                assert lid in all_log_ids, f"Chain {c['chain_id']} cites non-existent log_id '{lid}'"
    print("  [OK] All log_ids cited in mock_chains.json exist in mock_logs.json")

    # ---------------------------------------------------------
    # 4. Validate mock_graph.json
    # ---------------------------------------------------------
    print("[4/5] Checking data/mock_graph.json...")
    graph_file = root / "data" / "mock_graph.json"
    assert graph_file.exists(), "data/mock_graph.json missing"
    with open(graph_file, "r", encoding="utf-8") as f:
        graph = json.load(f)

    assert "nodes" in graph and "edges" in graph, "GRAPH dict must contain 'nodes' and 'edges'"
    nodes = graph["nodes"]
    edges = graph["edges"]
    node_ids = {n["id"] for n in nodes}

    # Verify at least one gray blocked IP
    gray_blocked_ips = [
        n for n in nodes if n.get("color") == "gray" and n.get("type") == "ip"
    ]
    assert len(gray_blocked_ips) >= 1, "mock_graph.json must have at least one gray blocked IP node"
    print(f"  [OK] Found gray blocked IP node: {gray_blocked_ips[0]['id']}")

    # Verify at least one is_pivot node
    pivot_nodes = [n for n in nodes if n.get("is_pivot") is True]
    assert len(pivot_nodes) >= 1, "mock_graph.json must have at least one is_pivot node"
    print(f"  [OK] Found is_pivot node: {pivot_nodes[0]['id']}")

    # Verify green neighbor nodes exist
    green_nodes = [n for n in nodes if n.get("color") == "green"]
    assert len(green_nodes) >= 3, f"mock_graph.json should include green neighbor nodes, found {len(green_nodes)}"
    print(f"  [OK] Found {len(green_nodes)} green neighbor nodes for context")

    # Verify attack path edges
    attack_edges = [e for e in edges if e.get("on_attack_path") is True]
    assert len(attack_edges) >= 5, "mock_graph.json must have edges marked on_attack_path = True"

    # Edge endpoints and log_id validation
    for e in edges:
        assert e["source"] in node_ids, f"Edge source '{e['source']}' not in nodes"
        assert e["target"] in node_ids, f"Edge target '{e['target']}' not in nodes"
        if "log_id" in e:
            assert e["log_id"] in all_log_ids, f"Edge cites non-existent log_id '{e['log_id']}'"
    print(f"  [OK] All {len(edges)} edges connect valid nodes and cite valid log_ids")

    # ---------------------------------------------------------
    # 5. Validate mock_report.json
    # ---------------------------------------------------------
    print("[5/5] Checking data/mock_report.json...")
    report_file = root / "data" / "mock_report.json"
    assert report_file.exists(), "data/mock_report.json missing"
    with open(report_file, "r", encoding="utf-8") as f:
        report = json.load(f)

    for key in [
        "summary",
        "risk_score",
        "risk_rationale",
        "stages",
        "recommendations",
        "citations_verified",
    ]:
        assert key in report, f"mock_report.json missing key '{key}'"

    assert report["citations_verified"] is True, "mock_report.json must have citations_verified: True"
    assert 1 <= report["risk_score"] <= 100, "risk_score must be between 1 and 100"

    # Validate citations against mock_logs
    for s in report["stages"]:
        for lid in s["log_ids"]:
            assert lid in all_log_ids, f"Report stage {s['stage_no']} cites non-existent log_id '{lid}'"

    # Validate recommendations actions and targets
    allowed_actions = {
        "block_ip",
        "revoke_user_token",
        "isolate_host",
        "reset_credentials",
    }
    chain_entities = (
        set(c1_chain["entities"]["users"])
        | set(c1_chain["entities"]["ips"])
        | set(c1_chain["entities"]["hosts"])
        | set(c1_chain["entities"]["resources"])
    )
    for rec in report["recommendations"]:
        assert rec["action"] in allowed_actions, f"Invalid recommendation action '{rec['action']}'"
        assert rec["target"] in chain_entities, (
            f"Recommendation target '{rec['target']}' not in C-1 chain entities"
        )
    print("  [OK] All recommendations use allowed actions and target real chain entities")

    # Execute Member 2 evidence firewall validation
    c1_incident_logs = [r for r in logs if r["log_id"] in all_log_ids]
    assert validate_citations(report, c1_chain, c1_incident_logs) is True, (
        "Evidence firewall validate_citations() failed for mock_report.json"
    )
    print("  [OK] Member 2 evidence firewall validation passed (citations_verified: True)")

    print("\n[SUCCESS] All mock data and cross-references are 100% valid! Foundation is ready.")


if __name__ == "__main__":
    main()
