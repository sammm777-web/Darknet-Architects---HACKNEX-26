"""
tests/test_graph.py

Comprehensive test suite for backend/graph_builder.py covering:
- Red / green / blue color assignments
- Blocked IP turns gray with status 'isolated' (gray wins over red)
- Exactly one pivot node with highest betweenness centrality
- Attack-path edges flagged correctly
- JSON serializability via json.dumps
- Disconnected graph / chain with no path does not crash
- Green neighbor limit (<= 8)
- Integration test on data/mock_logs.json and data/mock_chains.json
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.graph_builder import build_graph


def test_colors_red_blue_green():
    """Verify red for chain entities, blue for sensitive resources/target host, green for others."""
    chain = {
        "chain_id": "TEST-1",
        "entities": {
            "users": ["alice"],
            "ips": ["10.0.0.5"],
            "hosts": ["WS-101", "SRV-TARGET"],
            "resources": ["confidential_db.vault"],
        },
        "stages": [
            {
                "stage_no": 1,
                "tactic": "Initial Access",
                "user": "alice",
                "src_ip": "10.0.0.5",
                "log_ids": ["L-1"],
            },
            {
                "stage_no": 2,
                "tactic": "Exfiltration",
                "user": "alice",
                "resource": "confidential_db.vault",
                "log_ids": ["L-2"],
            },
        ],
    }
    logs = [
        # Chain logs
        {
            "log_id": "L-1",
            "timestamp": "2026-10-07T10:00:00Z",
            "user": "alice",
            "src_ip": "10.0.0.5",
            "host": "WS-101",
            "action": "login",
            "resource": "WS-101",
        },
        {
            "log_id": "L-2",
            "timestamp": "2026-10-07T10:10:00Z",
            "user": "alice",
            "src_ip": "10.0.0.5",
            "host": "SRV-TARGET",
            "action": "exfiltrate",
            "resource": "confidential_db.vault",
        },
        # Normal background log
        {
            "log_id": "L-BG",
            "timestamp": "2026-10-07T09:50:00Z",
            "user": "bob_normal",
            "src_ip": "10.0.0.99",
            "host": "WS-101",
            "action": "file_read",
            "resource": "readme.txt",
        },
    ]

    graph = build_graph(chain, logs)
    node_map = {n["id"]: n for n in graph["nodes"]}

    # Red: chain entities
    assert node_map["alice"]["color"] == "red", f"alice expected red, got {node_map['alice']['color']}"
    assert node_map["10.0.0.5"]["color"] == "red", f"10.0.0.5 expected red, got {node_map['10.0.0.5']['color']}"
    assert node_map["WS-101"]["color"] == "red", f"WS-101 expected red, got {node_map['WS-101']['color']}"

    # Blue: sensitive resource or target host
    assert node_map["confidential_db.vault"]["color"] == "blue"
    assert node_map["SRV-TARGET"]["color"] == "blue"

    # Green: background entities
    assert node_map["bob_normal"]["color"] == "green"
    assert node_map["readme.txt"]["color"] == "green"
    assert node_map["10.0.0.99"]["color"] == "green"

    print("  [PASS] test_colors_red_blue_green")


def test_blocked_ip_turns_gray():
    """Verify any IP in blocked turns gray with status='isolated', even if it is a chain entity."""
    chain = {
        "chain_id": "TEST-BLOCKED",
        "entities": {
            "users": ["attacker"],
            "ips": ["198.51.100.1", "10.0.0.1"],
            "hosts": ["WS-1"],
            "resources": ["file.txt"],
        },
        "stages": [
            {
                "stage_no": 1,
                "user": "attacker",
                "src_ip": "198.51.100.1",
                "log_ids": ["L-BLK"],
            }
        ],
    }
    logs = [
        {
            "log_id": "L-BLK",
            "timestamp": "2026-10-07T12:00:00Z",
            "user": "attacker",
            "src_ip": "198.51.100.1",
            "host": "WS-1",
            "action": "login",
            "resource": "WS-1",
        }
    ]

    # IP 198.51.100.1 is in chain.entities (normally red), but is in blocked -> must be gray!
    graph = build_graph(chain, logs, blocked={"198.51.100.1"})
    node_map = {n["id"]: n for n in graph["nodes"]}

    blocked_node = node_map["198.51.100.1"]
    assert blocked_node["color"] == "gray", f"Blocked IP must be gray, got {blocked_node['color']}"
    assert blocked_node["status"] == "isolated", f"Blocked IP status must be isolated, got {blocked_node['status']}"

    # Unblocked chain node remains red and active
    assert node_map["attacker"]["color"] == "red"
    assert node_map["attacker"]["status"] == "active"

    print("  [PASS] test_blocked_ip_turns_gray")


def test_exactly_one_pivot():
    """Verify exactly one node in chain entities has is_pivot=True."""
    chain = {
        "chain_id": "TEST-PIVOT",
        "entities": {
            "users": ["u1", "u2"],
            "ips": ["10.0.0.1", "10.0.0.2"],
            "hosts": ["HOST-PIVOT", "HOST-TARGET"],
            "resources": ["target.res"],
        },
        "stages": [
            {"stage_no": 1, "user": "u1", "src_ip": "10.0.0.1", "log_ids": ["L-1"]},
            {"stage_no": 2, "user": "u2", "src_ip": "10.0.0.2", "log_ids": ["L-2"]},
        ],
    }
    logs = [
        {
            "log_id": "L-1",
            "timestamp": "2026-10-07T10:00:00Z",
            "user": "u1",
            "src_ip": "10.0.0.1",
            "host": "HOST-PIVOT",
            "action": "priv_esc",
            "resource": "u2",
        },
        {
            "log_id": "L-2",
            "timestamp": "2026-10-07T10:10:00Z",
            "user": "u2",
            "src_ip": "10.0.0.2",
            "host": "HOST-TARGET",
            "action": "collect",
            "resource": "target.res",
        },
    ]

    graph = build_graph(chain, logs)
    pivots = [n for n in graph["nodes"] if n["is_pivot"] is True]
    assert len(pivots) == 1, f"Expected exactly 1 pivot node, found {len(pivots)}: {pivots}"

    # Node size must scale with betweenness centrality: 20 + 60 * centrality
    for n in graph["nodes"]:
        assert n["size"] >= 20.0, f"Node size must be at least 20, got {n['size']}"

    print("  [PASS] test_exactly_one_pivot")


def test_attack_path_edges_flagged():
    """Verify edges on the attack path and chain log_ids have on_attack_path=True, others False."""
    chain = {
        "chain_id": "TEST-PATH",
        "entities": {
            "users": ["intruder"],
            "ips": ["192.168.1.50"],
            "hosts": ["SRV-1"],
            "resources": ["crown_jewels.db"],
        },
        "stages": [
            {
                "stage_no": 1,
                "user": "intruder",
                "src_ip": "192.168.1.50",
                "log_ids": ["L-ATTACK"],
            }
        ],
    }
    logs = [
        {
            "log_id": "L-ATTACK",
            "timestamp": "2026-10-07T11:00:00Z",
            "user": "intruder",
            "src_ip": "192.168.1.50",
            "host": "SRV-1",
            "action": "steal",
            "resource": "crown_jewels.db",
        },
        {
            "log_id": "L-NORMAL",
            "timestamp": "2026-10-07T11:05:00Z",
            "user": "clean_user",
            "src_ip": "192.168.1.200",
            "host": "SRV-1",
            "action": "ping",
            "resource": "SRV-1",
        },
    ]

    graph = build_graph(chain, logs)
    attack_edges = [e for e in graph["edges"] if e["on_attack_path"] is True]
    normal_edges = [e for e in graph["edges"] if e["on_attack_path"] is False]

    assert len(attack_edges) >= 1, "At least one edge must be marked on_attack_path=True"
    for e in attack_edges:
        assert e["log_id"] == "L-ATTACK"

    assert len(normal_edges) >= 1, "Background edges must be on_attack_path=False"
    for e in normal_edges:
        assert e["log_id"] == "L-NORMAL"

    print("  [PASS] test_attack_path_edges_flagged")


def test_output_passes_json_dumps():
    """Verify output contains strictly JSON-serializable types and dumps cleanly."""
    chain = {
        "chain_id": "TEST-JSON",
        "entities": {"users": ["u"], "ips": ["1.1.1.1"], "hosts": ["h"], "resources": ["r"]},
        "stages": [{"stage_no": 1, "user": "u", "log_ids": ["L-1"]}],
    }
    logs = [
        {
            "log_id": "L-1",
            "timestamp": "2026-10-07T10:00:00Z",
            "user": "u",
            "src_ip": "1.1.1.1",
            "host": "h",
            "action": "test",
            "resource": "r",
        }
    ]

    graph = build_graph(chain, logs)
    json_str = json.dumps(graph)
    assert len(json_str) > 0
    loaded = json.loads(json_str)
    assert "nodes" in loaded and "edges" in loaded

    print("  [PASS] test_output_passes_json_dumps")


def test_no_path_does_not_crash():
    """Verify a chain where no directed path exists between patient zero and target does not crash."""
    chain = {
        "chain_id": "TEST-NO-PATH",
        "entities": {
            "users": ["user_island_a", "user_island_b"],
            "ips": ["10.1.1.1", "10.2.2.2"],
            "hosts": ["HOST-A", "HOST-B"],
            "resources": ["res_a", "res_unreachable"],
        },
        "stages": [
            {
                "stage_no": 1,
                "user": "user_island_a",
                "src_ip": "10.1.1.1",
                "log_ids": ["L-ISLAND-1"],
            },
            {
                "stage_no": 2,
                "user": "user_island_b",
                "resource": "res_unreachable",
                "log_ids": ["L-ISLAND-2"],
            },
        ],
    }
    # Two disconnected components with no directed path between user_island_a and res_unreachable
    logs = [
        {
            "log_id": "L-ISLAND-1",
            "timestamp": "2026-10-07T10:00:00Z",
            "user": "user_island_a",
            "src_ip": "10.1.1.1",
            "host": "HOST-A",
            "action": "action_a",
            "resource": "res_a",
        },
        {
            "log_id": "L-ISLAND-2",
            "timestamp": "2026-10-07T10:20:00Z",
            "user": "user_island_b",
            "src_ip": "10.2.2.2",
            "host": "HOST-B",
            "action": "action_b",
            "resource": "res_unreachable",
        },
    ]

    # Must NOT raise NetworkXNoPath or crash
    graph = build_graph(chain, logs)
    assert len(graph["nodes"]) > 0
    # Chain's own edges must still be marked on_attack_path=True
    chain_edges = [e for e in graph["edges"] if e["on_attack_path"] is True]
    assert len(chain_edges) > 0

    print("  [PASS] test_no_path_does_not_crash")


def test_green_neighbors_limited_to_8():
    """Verify that when many normal background logs exist, green nodes are capped at at most 8."""
    chain = {
        "chain_id": "TEST-LIMIT",
        "entities": {"users": ["hacker"], "ips": ["10.0.0.1"], "hosts": ["WS-1"], "resources": ["loot"]},
        "stages": [{"stage_no": 1, "user": "hacker", "log_ids": ["L-HACK"]}],
    }
    logs = [
        {
            "log_id": "L-HACK",
            "timestamp": "2026-10-07T10:00:00Z",
            "user": "hacker",
            "src_ip": "10.0.0.1",
            "host": "WS-1",
            "action": "steal",
            "resource": "loot",
        }
    ]
    # Add 20 unique green background nodes
    for i in range(20):
        logs.append(
            {
                "log_id": f"L-BG-{i}",
                "timestamp": f"2026-10-07T09:{i:02d}:00Z",
                "user": f"normal_user_{i}",
                "src_ip": f"192.168.1.{i+10}",
                "host": f"NORMAL-HOST-{i}",
                "action": "read",
                "resource": f"file_{i}.txt",
            }
        )

    graph = build_graph(chain, logs)
    green_nodes = [n for n in graph["nodes"] if n["color"] == "green"]
    assert len(green_nodes) <= 8, f"Green nodes must be <= 8, found {len(green_nodes)}"

    print("  [PASS] test_green_neighbors_limited_to_8")


def test_integration_with_mock_c1():
    """Verify build_graph works seamlessly with project mock data (C-1 scenario)."""
    with open(root_dir / "data" / "mock_chains.json", "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(root_dir / "data" / "mock_logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    c1_logs = [r for r in logs if r.get("chain_id") == "C-1"]

    blocked_ip = "203.0.113.199"
    graph = build_graph(c1_chain, c1_logs, blocked={blocked_ip})

    node_map = {n["id"]: n for n in graph["nodes"]}
    assert blocked_ip in node_map
    assert node_map[blocked_ip]["color"] == "gray"
    assert node_map[blocked_ip]["status"] == "isolated"

    pivots = [n for n in graph["nodes"] if n["is_pivot"] is True]
    assert len(pivots) == 1

    green_nodes = [n for n in graph["nodes"] if n["color"] == "green"]
    assert 1 <= len(green_nodes) <= 8

    attack_edges = [e for e in graph["edges"] if e["on_attack_path"] is True]
    assert len(attack_edges) >= 5

    # JSON serializability
    json_bytes = json.dumps(graph)
    assert len(json_bytes) > 0

    print("  [PASS] test_integration_with_mock_c1")


def test_context_logs_adds_green_nodes_without_changing_red_nodes():
    """Verify that passing context_logs introduces green background nodes while leaving red chain nodes unchanged."""
    with open(root_dir / "data" / "mock_chains.json", "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(root_dir / "data" / "mock_logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    c1_attack_logs = [r for r in logs if r.get("chain_id") == "C-1" and r.get("is_attack") is True]
    c1_bg_logs = [r for r in logs if r.get("chain_id") == "C-1" and r.get("is_attack") is False]

    # Graph built strictly with attack logs (no context)
    g_base = build_graph(c1_chain, c1_attack_logs)
    red_nodes_base = {n["id"] for n in g_base["nodes"] if n["color"] == "red"}
    green_nodes_base = {n["id"] for n in g_base["nodes"] if n["color"] == "green"}
    assert len(green_nodes_base) == 0, "No green nodes expected when only chain logs are provided"
    assert len(red_nodes_base) > 0, "Chain entities must be red"

    # Graph built with context_logs passed
    g_with_ctx = build_graph(c1_chain, c1_attack_logs, context_logs=c1_bg_logs)
    red_nodes_with_ctx = {n["id"] for n in g_with_ctx["nodes"] if n["color"] == "red"}
    green_nodes_with_ctx = {n["id"] for n in g_with_ctx["nodes"] if n["color"] == "green"}

    # Assertions: red nodes are completely unchanged, green nodes are present and capped at 8
    assert red_nodes_base == red_nodes_with_ctx, (
        f"Red nodes changed! Base: {red_nodes_base} != With Context: {red_nodes_with_ctx}"
    )
    assert len(green_nodes_with_ctx) > 0, "Graph with context_logs must have green nodes"
    assert len(green_nodes_with_ctx) <= 8, f"Green nodes must be <= 8, found {len(green_nodes_with_ctx)}"

    # Chain edges must remain unchanged on attack path
    base_attack_lids = {e["log_id"] for e in g_base["edges"] if e["on_attack_path"]}
    ctx_attack_lids = {e["log_id"] for e in g_with_ctx["edges"] if e["on_attack_path"]}
    assert base_attack_lids == ctx_attack_lids, "Chain attack path edges must remain unchanged"

    print("  [PASS] test_context_logs_adds_green_nodes_without_changing_red_nodes")


def main():
    print("[*] Running test suite for backend/graph_builder.py...")
    test_colors_red_blue_green()
    test_blocked_ip_turns_gray()
    test_exactly_one_pivot()
    test_attack_path_edges_flagged()
    test_output_passes_json_dumps()
    test_no_path_does_not_crash()
    test_green_neighbors_limited_to_8()
    test_integration_with_mock_c1()
    test_context_logs_adds_green_nodes_without_changing_red_nodes()
    print("\n[SUCCESS] All 9 graph tests passed successfully!")


if __name__ == "__main__":
    main()
