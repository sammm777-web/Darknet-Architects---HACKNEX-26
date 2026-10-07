"""
Unit test for Attack Graph data structures, Hierarchical SVG/HTML5 Generation,
PyVis backward-compatibility, Node Inspection, Filtering, Attack Path Highlighting,
and Edge Cases.
"""

from data.graph_demo_data import (
    CLEAN_GRAPH,
    USB_EXFILTRATION_GRAPH,
    LATERAL_MOVEMENT_GRAPH,
    get_graph_for_scenario,
    SCENARIO_GRAPHS
)
from components.attack_graph import (
    create_pyvis_network,
    generate_hierarchical_graph_html,
    compute_hierarchical_positions,
    extract_clean_protocol
)

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

    # 5. Test Hierarchical Positions Computation
    print("\nTesting Hierarchical Layout Positioning...")
    clean_pos = compute_hierarchical_positions(CLEAN_GRAPH["nodes"], CLEAN_GRAPH["edges"], "clean_logs")
    assert clean_pos["dc-01"][1] < clean_pos["file-srv"][1]
    assert clean_pos["dc-01"][1] < clean_pos["wkst-01"][1]
    assert clean_pos["file-srv"][1] < clean_pos["doc-budget"][1]
    assert clean_pos["wkst-01"][1] < clean_pos["usr-alice"][1]
    # Check left vs right branching
    assert clean_pos["file-srv"][0] < clean_pos["dc-01"][0] < clean_pos["wkst-01"][0]
    assert clean_pos["doc-budget"][0] < clean_pos["dc-01"][0] < clean_pos["usr-alice"][0]
    print("  [OK] Clean Logs exact 3-level tree hierarchy verified (DC -> FileServer/WS-ALPHA -> Budget/alice)")

    # 6. Test Protocol Extractor
    assert extract_clean_protocol("SMB_CONNECT (Port 445)", "REMOTE CONNECTION") == "SMB_CONNECT"
    assert extract_clean_protocol("AUTH_TGS (Port 88)", "ACCESS") == "AUTH_TGS"
    assert extract_clean_protocol("LOGIN (Kerberos)", "LOGIN") == "LOGON"
    print("  [OK] Protocol label extraction verified (SMB_CONNECT, AUTH_TGS, LOGON)")

    # 7. Test Hierarchical SVG/HTML5 Generation
    print("\nTesting Hierarchical HTML5 Graph Generation & Controls...")
    for s_id in ["clean_logs", "usb_exfiltration", "lateral_movement"]:
        g = get_graph_for_scenario(s_id)
        # Test standard
        html = generate_hierarchical_graph_html(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=None,
            show_labels=True,
            highlight_attack=False,
            scenario_id=s_id,
            height=460
        )
        assert len(html) > 500
        assert "<svg" in html
        assert "soc-node-card" in html

        # Test with highlighted attack path
        html_hl = generate_hierarchical_graph_html(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=g["nodes"][0]["id"],
            show_labels=True,
            highlight_attack=True,
            scenario_id=s_id,
            height=460
        )
        assert len(html_hl) > 500
        assert "arrow-attack" in html_hl

        # Test with hidden labels
        html_nolabel = generate_hierarchical_graph_html(
            nodes=g["nodes"],
            edges=g["edges"],
            selected_node_id=None,
            show_labels=False,
            highlight_attack=False,
            scenario_id=s_id,
            height=460
        )
        assert len(html_nolabel) > 500

        print(f"  [OK] Hierarchical HTML successfully generated for {s_id} (All Variants Passed)")

    # 8. Test PyVis Compatibility
    print("\nTesting PyVis Backward-Compatibility Layer...")
    for s_id in ["clean_logs", "usb_exfiltration", "lateral_movement"]:
        g = get_graph_for_scenario(s_id)
        net = create_pyvis_network(nodes=g["nodes"], edges=g["edges"], height=500)
        html = net.generate_html()
        assert len(html) > 100
        print(f"  [OK] PyVis layer verified for {s_id}")

    # 9. Test Empty & Corrupt Input Handling
    html_empty = generate_hierarchical_graph_html(nodes=[], edges=[], height=460)
    assert "<svg" in html_empty
    print("  [OK] Empty graph handled gracefully with valid minimal container")

    print("\nALL GRAPH & CONTROLS TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
