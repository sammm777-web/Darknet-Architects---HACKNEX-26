"""
Unit test for Attack Graph data structures, PyVis generation, Node Inspection,
Filtering, Attack Path Highlighting, and Edge Cases.
"""

from data.graph_demo_data import (
    CLEAN_GRAPH,
    USB_EXFILTRATION_GRAPH,
    LATERAL_MOVEMENT_GRAPH,
    get_graph_for_scenario,
    SCENARIO_GRAPHS
)
from components.attack_graph import create_pyvis_network

def run_tests():
    print("Testing Graph Demo Data Structures...")
    
    # 1. Test Clean Logs Graph
    assert len(CLEAN_GRAPH["nodes"]) == 5
    assert len(CLEAN_GRAPH["edges"]) == 4
    for node in CLEAN_GRAPH["nodes"]:
        assert "risk" in node
        assert "first_seen" in node
        assert "last_activity" in node
    print("  [OK] Clean Logs graph structure verified with rich SOC telemetry (5 nodes, 4 edges)")

    # 2. Test USB Exfiltration Graph
    assert len(USB_EXFILTRATION_GRAPH["nodes"]) == 5
    assert len(USB_EXFILTRATION_GRAPH["edges"]) == 4
    # Verify node types
    node_types_usb = {n["type"] for n in USB_EXFILTRATION_GRAPH["nodes"]}
    assert "USER" in node_types_usb
    assert "DEVICE" in node_types_usb
    assert "FILE" in node_types_usb
    assert "USB DEVICE" in node_types_usb
    assert "ATTACKER" in node_types_usb
    print("  [OK] USB Exfiltration graph node taxonomy verified")

    # 3. Test Lateral Movement Graph
    assert len(LATERAL_MOVEMENT_GRAPH["nodes"]) == 6
    assert len(LATERAL_MOVEMENT_GRAPH["edges"]) == 5
    edge_types_lat = {e["type"] for e in LATERAL_MOVEMENT_GRAPH["edges"]}
    assert "LATERAL MOVEMENT" in edge_types_lat
    assert "REMOTE CONNECTION" in edge_types_lat
    print("  [OK] Lateral Movement graph attack vectors verified")

    # 4. Test Scenario Selector Function
    for s_id in ["clean_logs", "usb_exfiltration", "lateral_movement"]:
        g = get_graph_for_scenario(s_id)
        assert "nodes" in g
        assert "edges" in g
        print(f"  [OK] get_graph_for_scenario('{s_id}') -> {g['name']}")

    # 5. Test PyVis Network Generation with Filtering & Highlighting
    print("\nTesting PyVis Network Generation & Controls...")
    for s_id in ["clean_logs", "usb_exfiltration", "lateral_movement"]:
        g = get_graph_for_scenario(s_id)
        # Test default
        net = create_pyvis_network(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=None,
            show_labels=True,
            highlight_attack=False,
            height=500
        )
        html = net.generate_html()
        assert len(html) > 500
        assert "vis" in html.lower() or "network" in html.lower()

        # Test with highlighted attack path
        net_hl = create_pyvis_network(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=g["nodes"][0]["id"],
            show_labels=True,
            highlight_attack=True,
            height=500
        )
        html_hl = net_hl.generate_html()
        assert len(html_hl) > 500

        # Test with hidden labels
        net_nolabel = create_pyvis_network(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=None,
            show_labels=False,
            highlight_attack=False,
            height=500
        )
        html_nolabel = net_nolabel.generate_html()
        assert len(html_nolabel) > 500

        print(f"  [OK] PyVis HTML successfully generated for {s_id} (All Control Variants Passed)")

    # 6. Test Nodes-Only Graph Handling (0 edges)
    nodes_only = [{"id": "n1", "label": "Host A", "type": "DEVICE", "status": "SAFE"}]
    net_nodes_only = create_pyvis_network(nodes=nodes_only, edges=[], height=500)
    html_nodes_only = net_nodes_only.generate_html()
    assert len(html_nodes_only) > 200
    print("  [OK] Nodes-only graph successfully generated without edges")

    # 7. Test Empty & Corrupt Input Handling
    net_empty = create_pyvis_network(nodes=[], edges=[], height=500)
    html_empty = net_empty.generate_html()
    assert len(html_empty) > 100
    print("  [OK] Empty graph handled gracefully with valid minimal container")

    print("\nALL GRAPH & CONTROLS TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
