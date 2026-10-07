"""
Unit test for Attack Graph data structures, PyVis generation, and empty graph handling.
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
    print("  [OK] Clean Logs graph structure verified (5 nodes, 4 edges)")

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

    # 5. Test PyVis Network Generation
    print("\nTesting PyVis Network Generation...")
    for s_id in ["clean_logs", "usb_exfiltration", "lateral_movement"]:
        g = get_graph_for_scenario(s_id)
        net = create_pyvis_network(g, height=500)
        html = net.generate_html()
        assert len(html) > 500
        assert "vis" in html.lower() or "network" in html.lower()
        print(f"  [OK] PyVis HTML successfully generated for {s_id} (HTML length: {len(html)} bytes)")

    # 6. Test Nodes-Only Graph Handling (0 edges)
    nodes_only = {
        "name": "Isolated Nodes",
        "nodes": [{"id": "n1", "label": "Host A", "type": "DEVICE", "status": "SAFE"}],
        "edges": []
    }
    net_nodes_only = create_pyvis_network(nodes_only, height=500)
    html_nodes_only = net_nodes_only.generate_html()
    assert len(html_nodes_only) > 200
    print("  [OK] Nodes-only graph successfully generated without edges")

    print("\nALL GRAPH TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
