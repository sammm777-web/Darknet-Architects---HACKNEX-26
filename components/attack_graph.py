"""
Structured Hierarchical Attack-Path Graph Component for SOC Command Center.
Renders an enterprise hierarchical tree / attack-flow visualization with:
- Centered root nodes and structured multi-level branches (Level 0 -> Level 1 -> Level 2...)
- Rounded card nodes with entity icons, names, and category badges
- Clean curved arrows with protocol labels (SMB_CONNECT, AUTH_TGS, LOGON, etc.)
- Left-side compact legend (Node Types & Relationship Types)
- Active attack-path emphasis with crimson highlighting
- Full node inspection telemetry and top-level filter/highlight/reset controls

Visual Theme:
- Background: #0C0C0E / #05080E
- Primary text: #F5F2ED
- Secondary text: #9A968F
- Threat / Alerts: #E63946 (#7A1F2B)
- Hosts / Devices: #00E5C7
- Users: #F59E0B
- Files: #8A94A6
"""

import json
import textwrap
from typing import Dict, Any, Optional, List, Tuple
import streamlit as st
import streamlit.components.v1 as components

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


# -------------------------------------------------------------------------
# Node Taxonomy Configuration
# -------------------------------------------------------------------------
ENTITY_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "ATTACKER": {
        "color": "#E63946",
        "bg": "rgba(230, 57, 70, 0.14)",
        "border": "#E63946",
        "icon": "⚔️",
        "label": "ATTACK / CRITICAL TARGET"
    },
    "TARGET": {
        "color": "#E63946",
        "bg": "rgba(230, 57, 70, 0.14)",
        "border": "#E63946",
        "icon": "🎯",
        "label": "ATTACK / CRITICAL TARGET"
    },
    "SERVER": {
        "color": "#00E5C7",
        "bg": "rgba(0, 229, 199, 0.10)",
        "border": "#00E5C7",
        "icon": "🖧",
        "label": "HOST / SERVER"
    },
    "DEVICE": {
        "color": "#00E5C7",
        "bg": "rgba(0, 229, 199, 0.10)",
        "border": "#00E5C7",
        "icon": "💻",
        "label": "HOST / DEVICE"
    },
    "IP": {
        "color": "#00E5C7",
        "bg": "rgba(0, 229, 199, 0.10)",
        "border": "#00E5C7",
        "icon": "🌐",
        "label": "HOST / IP"
    },
    "USER": {
        "color": "#F59E0B",
        "bg": "rgba(245, 158, 11, 0.12)",
        "border": "#F59E0B",
        "icon": "👤",
        "label": "USER"
    },
    "FILE": {
        "color": "#8A94A6",
        "bg": "rgba(138, 148, 166, 0.10)",
        "border": "#8A94A6",
        "icon": "📄",
        "label": "FILE"
    },
    "USB DEVICE": {
        "color": "#FBBF24",
        "bg": "rgba(251, 191, 36, 0.12)",
        "border": "#FBBF24",
        "icon": "🔌",
        "label": "REMOVABLE MEDIA"
    },
    "USB": {
        "color": "#FBBF24",
        "bg": "rgba(251, 191, 36, 0.12)",
        "border": "#FBBF24",
        "icon": "🔌",
        "label": "REMOVABLE MEDIA"
    }
}

DEFAULT_TAXONOMY = {
    "color": "#8A94A6",
    "bg": "rgba(138, 148, 166, 0.10)",
    "border": "#162338",
    "icon": "📦",
    "label": "ENTITY"
}


# -------------------------------------------------------------------------
# PyVis Network Compatibility Wrapper (Preserved for unit test suites)
# -------------------------------------------------------------------------
def create_pyvis_network(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    selected_node_id: Optional[str] = None,
    show_labels: bool = True,
    highlight_attack: bool = False,
    height: int = 500
) -> Any:
    """
    Builds a PyVis network instance for backward-compatibility.
    """
    if not PYVIS_AVAILABLE:
        class DummyNet:
            def generate_html(self):
                return "<div id='mynetwork'>PyVis not installed</div>"
        return DummyNet()

    net = Network(
        height=f"{height}px",
        width="100%",
        bgcolor="#05080E",
        font_color="#F5F2ED",
        directed=True
    )
    for node in nodes:
        node_id = str(node.get("id", ""))
        raw_label = str(node.get("label", node_id))
        category = str(node.get("type", "DEVICE")).upper()
        tax = ENTITY_TAXONOMY.get(category, DEFAULT_TAXONOMY)
        net.add_node(
            n_id=node_id,
            label=raw_label if show_labels else " ",
            shape="box",
            color={"background": "#0D1422", "border": tax["color"]}
        )
    for edge in edges:
        source = str(edge.get("source", edge.get("from", "")))
        target = str(edge.get("target", edge.get("to", "")))
        label = str(edge.get("label", ""))
        net.add_edge(source=source, to=target, label=label if show_labels else "")
    return net


# -------------------------------------------------------------------------
# Hierarchical Layout Geometry & Node Positioning Algorithm
# -------------------------------------------------------------------------
def compute_hierarchical_positions(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    scenario_id: str = "clean_logs",
    canvas_w: int = 880,
    canvas_h: int = 420
) -> Dict[str, Tuple[int, int]]:
    """
    Computes deterministic, structured (x, y) coordinates for nodes in a clean
    hierarchical attack-path tree layout.
    """
    node_ids = [str(n.get("id", "")) for n in nodes]
    positions: Dict[str, Tuple[int, int]] = {}

    # 1. Clean Logs Scenario (Exact structured hierarchy specified in requirements)
    # Hierarchy:
    #                   Domain Controller (dc-01)
    #                   /                       \
    #          File Server (file-srv)          WS-ALPHA (wkst-01)
    #               |                                   |
    #   Quarterly_Budget.xlsx (doc-budget)       alice (usr-alice)
    clean_log_ids = {"dc-01", "file-srv", "wkst-01", "usr-alice", "doc-budget"}
    if clean_log_ids.issubset(set(node_ids)) or scenario_id == "clean_logs":
        positions["dc-01"] = (440, 58)
        positions["file-srv"] = (230, 195)
        positions["wkst-01"] = (650, 195)
        positions["doc-budget"] = (230, 345)
        positions["usr-alice"] = (650, 345)
        return positions

    # 2. USB Exfiltration Scenario (Top-to-bottom structured attack path)
    if scenario_id == "usb_exfiltration" or "usb-042" in node_ids:
        order = ["usr-john", "wkst-042", "doc-sensitive", "usb-042", "ext-drop"]
        y_coords = [48, 132, 218, 304, 390]
        for i, n_id in enumerate(order):
            if n_id in node_ids:
                positions[n_id] = (440, y_coords[i])
        return positions

    # 3. Lateral Movement Scenario (Multi-stage lateral pivot tree)
    if scenario_id == "lateral_movement" or "attacker-c2" in node_ids:
        # Structured 2-column or 3-level pivot tree
        positions["attacker-c2"] = (160, 65)
        positions["wkst-compromised"] = (440, 65)
        positions["usr-compromised"] = (720, 65)
        positions["srv-internal"] = (720, 245)
        positions["wkst-second"] = (440, 245)
        positions["dc-crown-jewel"] = (160, 245)
        return positions

    # 4. General Topological / Level-Based Hierarchical Layout for Custom Datasets
    if NETWORKX_AVAILABLE:
        G = nx.DiGraph()
        for n in nodes:
            G.add_node(str(n.get("id", "")))
        for e in edges:
            G.add_edge(str(e.get("source", "")), str(e.get("target", "")))
        
        # Calculate levels from in-degree 0 roots
        levels: Dict[str, int] = {}
        roots = [n for n in G.nodes if G.in_degree(n) == 0]
        if not roots and G.nodes:
            roots = [list(G.nodes)[0]]
        
        for root in roots:
            levels[root] = 0
            for target, length in nx.single_source_shortest_path_length(G, root).items():
                levels[target] = max(levels.get(target, 0), length)
        
        # Assign unreached nodes to level 0
        for n in G.nodes:
            if n not in levels:
                levels[n] = 0

        # Group nodes by level
        level_groups: Dict[int, List[str]] = {}
        for n_id, lvl in levels.items():
            level_groups.setdefault(lvl, []).append(n_id)

        max_lvl = max(level_groups.keys()) if level_groups else 0
        lvl_spacing = (canvas_h - 100) / max(1, max_lvl)

        for lvl, group in level_groups.items():
            y = int(55 + lvl * lvl_spacing)
            count = len(group)
            for idx, n_id in enumerate(group):
                x = int(canvas_w * (idx + 1) / (count + 1))
                positions[n_id] = (x, y)
        return positions

    # Fallback: simple evenly-spaced layout
    count = len(nodes)
    for i, n in enumerate(nodes):
        positions[str(n.get("id", ""))] = (
            int(canvas_w * (i + 1) / (count + 1)),
            int(canvas_h / 2)
        )
    return positions


# -------------------------------------------------------------------------
# Clean Protocol Label Extractor
# -------------------------------------------------------------------------
def extract_clean_protocol(label: str, edge_type: str) -> str:
    """
    Extracts a concise, professional protocol label (e.g. SMB_CONNECT, AUTH_TGS, LOGON).
    """
    if not label:
        return edge_type
    
    clean = label.split("(")[0].strip()
    clean = clean.replace("FILE READ", "FILE_READ").replace("FILE ACCESS", "FILE_ACCESS")
    clean = clean.replace("LOGIN", "LOGON")
    return clean


# -------------------------------------------------------------------------
# Hierarchical SVG / HTML5 Attack Graph Generator
# -------------------------------------------------------------------------
def generate_hierarchical_graph_html(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    selected_node_id: Optional[str] = None,
    show_labels: bool = True,
    highlight_attack: bool = False,
    scenario_id: str = "clean_logs",
    height: int = 480
) -> str:
    """
    Generates a high-contrast, structured hierarchical attack graph visualization.
    Renders rounded card nodes, curved Bézier connection paths, protocol labels,
    and active attack-path emphasis.
    """
    canvas_w = 880
    canvas_h = max(400, height - 40)
    
    # Compute deterministic hierarchical positions
    positions = compute_hierarchical_positions(
        nodes=nodes,
        edges=edges,
        scenario_id=scenario_id,
        canvas_w=canvas_w,
        canvas_h=canvas_h
    )

    card_w = 175
    card_h = 54

    # Build Edge SVG Elements
    edges_svg = []
    for edge in edges:
        s_id = str(edge.get("source", edge.get("from", "")))
        t_id = str(edge.get("target", edge.get("to", "")))

        if s_id not in positions or t_id not in positions:
            continue

        x1, y1 = positions[s_id]
        x2, y2 = positions[t_id]
        raw_label = str(edge.get("label", ""))
        edge_type = str(edge.get("type", "ACCESS")).upper()
        edge_status = str(edge.get("status", "NORMAL")).upper()

        protocol = extract_clean_protocol(raw_label, edge_type)

        # Severity & Attack Path Classification
        is_attack_edge = (
            edge_status in ["ATTACK", "LATERAL MOVEMENT", "EXFILTRATION"] or
            edge_type in ["LATERAL MOVEMENT", "EXFILTRATION"]
        )
        is_suspicious_edge = edge_status in ["SUSPICIOUS"]

        # Default Edge Styles
        if is_attack_edge:
            stroke_color = "#E63946"
            stroke_width = 2.8
            dash_array = "none"
            marker_id = "arrow-attack"
            label_text_color = "#E63946"
            label_bg_border = "#E63946"
        elif is_suspicious_edge:
            stroke_color = "#F59E0B"
            stroke_width = 2.0
            dash_array = "5,4"
            marker_id = "arrow-suspicious"
            label_text_color = "#F59E0B"
            label_bg_border = "#F59E0B"
        else:
            stroke_color = "#00E5C7" if edge_status == "BENIGN" else "#8A94A6"
            stroke_width = 1.4
            dash_array = "none"
            marker_id = "arrow-normal" if edge_status == "BENIGN" else "arrow-muted"
            label_text_color = "#9A968F"
            label_bg_border = "#162338"

        edge_opacity = 1.0
        if highlight_attack:
            if is_attack_edge:
                stroke_color = "#E63946"
                stroke_width = 3.2
                edge_opacity = 1.0
                marker_id = "arrow-attack"
            else:
                stroke_color = "#162338"
                stroke_width = 1.0
                edge_opacity = 0.22
                marker_id = "arrow-muted"

        # Calculate connection anchor points
        # If target is below source: from bottom of source to top of target
        if y2 > y1 + 30:
            start_x, start_y = x1, y1 + card_h // 2
            end_x, end_y = x2, y2 - card_h // 2 - 4
            ctrl_y1 = start_y + (end_y - start_y) * 0.45
            ctrl_y2 = start_y + (end_y - start_y) * 0.55
            path_d = f"M {start_x} {start_y} C {start_x} {ctrl_y1}, {end_x} {ctrl_y2}, {end_x} {end_y}"
            mid_x = (start_x + end_x) / 2
            mid_y = (start_y + end_y) / 2
        elif y2 < y1 - 30:
            start_x, start_y = x1, y1 - card_h // 2
            end_x, end_y = x2, y2 + card_h // 2 + 4
            ctrl_y1 = start_y + (end_y - start_y) * 0.45
            ctrl_y2 = start_y + (end_y - start_y) * 0.55
            path_d = f"M {start_x} {start_y} C {start_x} {ctrl_y1}, {end_x} {ctrl_y2}, {end_x} {end_y}"
            mid_x = (start_x + end_x) / 2
            mid_y = (start_y + end_y) / 2
        else:
            # Horizontal connection
            if x2 > x1:
                start_x, start_y = x1 + card_w // 2, y1
                end_x, end_y = x2 - card_w // 2 - 4, y2
            else:
                start_x, start_y = x1 - card_w // 2, y1
                end_x, end_y = x2 + card_w // 2 + 4, y2
            path_d = f"M {start_x} {start_y} L {end_x} {end_y}"
            mid_x = (start_x + end_x) / 2
            mid_y = (start_y + end_y) / 2

        # Protocol badge label
        label_pill_w = max(70, len(protocol) * 7 + 16)
        label_svg = ""
        if show_labels and protocol:
            label_svg = f"""
            <g class="soc-edge-label" opacity="{edge_opacity}">
                <rect x="{mid_x - label_pill_w / 2}" y="{mid_y - 9}" width="{label_pill_w}" height="18" rx="4"
                      fill="#070C14" stroke="{label_bg_border}" stroke-width="1" />
                <text x="{mid_x}" y="{mid_y + 3.5}" text-anchor="middle"
                      font-family="'JetBrains Mono', monospace" font-size="9.5" font-weight="600" fill="{label_text_color}">
                    {protocol}
                </text>
            </g>
            """

        edges_svg.append(f"""
        <g class="soc-edge-group">
            <path d="{path_d}" fill="none" stroke="{stroke_color}" stroke-width="{stroke_width}"
                  stroke-dasharray="{dash_array}" opacity="{edge_opacity}"
                  marker-end="url(#{marker_id})" />
            {label_svg}
        </g>
        """)

    # Build Node SVG Elements
    nodes_svg = []
    for node in nodes:
        n_id = str(node.get("id", ""))
        if n_id not in positions:
            continue

        x, y = positions[n_id]
        raw_label = str(node.get("label", n_id))
        category = str(node.get("type", "DEVICE")).upper()
        status = str(node.get("status", "SAFE")).upper()
        risk = str(node.get("risk", "LOW")).upper()

        tax = ENTITY_TAXONOMY.get(category, DEFAULT_TAXONOMY)
        accent_color = tax["color"]
        icon = tax["icon"]
        cat_label = tax["label"]

        # Override for compromised / attacker nodes
        is_compromised = status in ["COMPROMISED", "MALICIOUS", "TARGET"] or category in ["ATTACKER"]
        if is_compromised and category not in ["ATTACKER", "TARGET"]:
            accent_color = "#E63946"

        # Inspection Selection State
        is_selected = (selected_node_id == n_id)

        node_opacity = 1.0
        if highlight_attack:
            if is_compromised:
                node_opacity = 1.0
            else:
                node_opacity = 0.32

        card_stroke = accent_color if is_selected else ("#E63946" if is_compromised else "#162338")
        card_stroke_w = "2" if (is_selected or is_compromised) else "1"
        card_bg = "#111A2C" if is_selected else "#0D1422"

        # Truncate label cleanly if too wide
        display_name = raw_label
        if len(display_name) > 22:
            display_name = display_name[:20] + "…"

        node_top_left_x = x - card_w // 2
        node_top_left_y = y - card_h // 2

        nodes_svg.append(f"""
        <g class="soc-node-card" id="node-{n_id}" opacity="{node_opacity}" style="cursor: pointer;">
            <!-- Outer Card Container -->
            <rect x="{node_top_left_x}" y="{node_top_left_y}" width="{card_w}" height="{card_h}" rx="6"
                  fill="{card_bg}" stroke="{card_stroke}" stroke-width="{card_stroke_w}" />
            
            <!-- Left Icon Badge Box -->
            <rect x="{node_top_left_x + 8}" y="{node_top_left_y + 10}" width="{card_h - 20}" height="{card_h - 20}" rx="4"
                  fill="{tax['bg']}" stroke="{accent_color}" stroke-width="1" />
            <text x="{node_top_left_x + 8 + (card_h - 20)/2}" y="{node_top_left_y + 10 + (card_h - 20)/2 + 4.5}"
                  text-anchor="middle" font-size="14">
                {icon}
            </text>

            <!-- Entity Name -->
            <text x="{node_top_left_x + card_h}" y="{node_top_left_y + 22}"
                  font-family="'Inter', -apple-system, sans-serif" font-size="11.5" font-weight="600" fill="#F5F2ED">
                {display_name if show_labels else "●●●"}
            </text>

            <!-- Entity Category & Status Subtitle -->
            <text x="{node_top_left_x + card_h}" y="{node_top_left_y + 38}"
                  font-family="'JetBrains Mono', monospace" font-size="8.5" font-weight="600" fill="{accent_color}" letter-spacing="0.4px">
                {category} &bull; {status}
            </text>
            
            <title>{raw_label} | Type: {category} | Status: {status} | Risk: {risk}</title>
        </g>
        """)

    all_edges_markup = "\n".join(edges_svg)
    all_nodes_markup = "\n".join(nodes_svg)

    html_content = textwrap.dedent(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            html, body {{
                margin: 0;
                padding: 0;
                background-color: #05080E;
                overflow: hidden;
                font-family: 'Inter', -apple-system, sans-serif;
            }}
            .soc-hierarchical-svg {{
                display: block;
                width: 100%;
                height: {height}px;
                background-color: #05080E;
                border: 1px solid #162338;
                border-radius: 0 0 8px 8px;
            }}
            .soc-node-card:hover rect:first-child {{
                filter: brightness(1.2);
                stroke: #00E5C7 !important;
                stroke-width: 2px !important;
            }}
            .soc-edge-group:hover path {{
                stroke: #00E5C7 !important;
                stroke-width: 3px !important;
            }}
        </style>
    </head>
    <body>
        <svg class="soc-hierarchical-svg" viewBox="0 0 {canvas_w} {canvas_h}" preserveAspectRatio="xMidYMid meet">
            <defs>
                <!-- Directional Arrow Markers -->
                <marker id="arrow-normal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#00E5C7" />
                </marker>
                <marker id="arrow-attack" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                    <path d="M 0 1 L 9 5 L 0 9 z" fill="#E63946" />
                </marker>
                <marker id="arrow-suspicious" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#F59E0B" />
                </marker>
                <marker id="arrow-muted" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#8A94A6" />
                </marker>
            </defs>

            <!-- Background Grid Accent -->
            <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1" fill="rgba(255, 255, 255, 0.03)" />
            </pattern>
            <rect width="100%" height="100%" fill="url(#grid)" />

            <!-- Edge Relationship Curves -->
            {all_edges_markup}

            <!-- Node Hierarchy Cards -->
            {all_nodes_markup}
        </svg>
    </body>
    </html>
    """).strip()

    return html_content


# -------------------------------------------------------------------------
# Selected Entity Inspection Panel
# -------------------------------------------------------------------------
def render_selected_entity_panel(selected_node: Optional[Dict[str, Any]]) -> None:
    """
    Renders the detailed SELECTED ENTITY telemetry card.
    """
    if not selected_node:
        empty_html = textwrap.dedent("""
        <div class="soc-entity-panel">
            <div class="soc-entity-header">
                <span class="soc-entity-title">🔍 SELECTED ENTITY</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #9A968F;">STANDBY</span>
            </div>
            <div class="soc-entity-empty">
                <span style="font-size: 1.5rem; margin-bottom: 0.4rem;">🎯</span>
                <div><strong>No entity selected.</strong></div>
                <div style="font-size: 0.74rem; color: #5A6478; margin-top: 0.25rem;">
                    Select an entity from the inspection dropdown above to inspect detailed SOC telemetry.
                </div>
            </div>
        </div>
        """).strip()
        st.markdown(empty_html, unsafe_allow_html=True)
        return

    label = selected_node.get("label", selected_node.get("id", "Unknown"))
    entity_type = str(selected_node.get("type", "UNKNOWN")).upper()
    status = str(selected_node.get("status", "ACTIVE")).upper()
    risk = str(selected_node.get("risk", "LOW")).upper()
    ip_addr = selected_node.get("ip", "N/A")
    device_name = selected_node.get("device", selected_node.get("os", "N/A"))
    first_seen = selected_node.get("first_seen", "00:00:00")
    last_activity = selected_node.get("last_activity", "00:00:00")

    risk_badge_class = "soc-badge-low"
    if risk == "CRITICAL":
        risk_badge_class = "soc-badge-critical"
    elif risk in ["HIGH", "MEDIUM"]:
        risk_badge_class = "soc-badge-high"

    status_color = "#00E5C7"
    if status in ["COMPROMISED", "MALICIOUS"]:
        status_color = "#E63946"
    elif status in ["SUSPICIOUS", "TARGET"]:
        status_color = "#F59E0B"

    extra_fields = []
    ignored_keys = {"id", "label", "type", "status", "risk", "ip", "device", "first_seen", "last_activity"}
    for k, v in selected_node.items():
        if k not in ignored_keys and v:
            clean_key = k.replace("_", " ").title()
            extra_fields.append((clean_key, str(v)))

    extra_cells_html = ""
    for k, v in extra_fields:
        extra_cells_html += f"""
        <div class="soc-entity-cell">
            <div class="soc-entity-key">{k}</div>
            <div class="soc-entity-val">{v}</div>
        </div>
        """

    panel_html = textwrap.dedent(f"""
    <div class="soc-entity-panel">
        <div class="soc-entity-header">
            <span class="soc-entity-title">🔍 SELECTED ENTITY: <strong style="color: #00E5C7;">{label}</strong></span>
            <div style="display: flex; gap: 0.4rem; align-items: center;">
                <span class="soc-scenario-badge {risk_badge_class}">RISK: {risk}</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; font-weight: 600; padding: 2px 7px; border-radius: 4px; background: rgba(230, 57, 70, 0.1); color: {status_color}; border: 1px solid rgba(255,255,255,0.08);">
                    {status}
                </span>
            </div>
        </div>
        <div class="soc-entity-grid">
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Entity Label</div>
                <div class="soc-entity-val" style="color: #00E5C7;">{label}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Entity Type</div>
                <div class="soc-entity-val">{entity_type}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Status</div>
                <div class="soc-entity-val" style="color: {status_color};">{status}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Risk Level</div>
                <div class="soc-entity-val"><span class="soc-scenario-badge {risk_badge_class}">{risk}</span></div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Associated IP</div>
                <div class="soc-entity-val">{ip_addr}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Device / Host</div>
                <div class="soc-entity-val">{device_name}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">First Seen</div>
                <div class="soc-entity-val">{first_seen}</div>
            </div>
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Last Activity</div>
                <div class="soc-entity-val">{last_activity}</div>
            </div>
            {extra_cells_html}
        </div>
    </div>
    """).strip()
    st.markdown(panel_html, unsafe_allow_html=True)


# -------------------------------------------------------------------------
# Left-Side Graph Legend Component
# -------------------------------------------------------------------------
def render_graph_legend_panel(attack_chains: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Renders the compact, professional SOC graph legend on the LEFT side.
    """
    chains_count = len(attack_chains) if attack_chains else 0
    attack_status_badge = (
        f'<span style="color: #E63946; font-family: \'JetBrains Mono\', monospace; font-size: 0.68rem; font-weight: 600;">ACTIVE CHAINS: {chains_count}</span>'
        if chains_count > 0
        else '<span style="color: #00E5C7; font-family: \'JetBrains Mono\', monospace; font-size: 0.68rem; font-weight: 600;">BASELINE SAFE</span>'
    )

    chains_html = ""
    if attack_chains:
        chains_list_items = ""
        for chain in attack_chains:
            chain_name = chain.get("name", "Malicious Chain")
            chain_ttp = chain.get("ttp", "")
            chain_status = chain.get("status", "Active")
            ttp_badge = f'<span style="color: #F59E0B; font-size: 0.65rem; margin-left: 4px;">[{chain_ttp}]</span>' if chain_ttp else ""
            chains_list_items += f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; padding: 0.25rem 0; border-bottom: 1px solid #162338; display: flex; justify-content: space-between;">
                <span>⚠️ {chain_name} {ttp_badge}</span>
                <span style="color: #E63946; font-size: 0.68rem;">{chain_status}</span>
            </div>
            """
        chains_html = f"""
        <div style="margin-top: 0.75rem; padding-top: 0.5rem; border-top: 1px solid #162338;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #9A968F; text-transform: uppercase; margin-bottom: 0.35rem; font-weight: 600;">
                DETECTED ATTACK PATH
            </div>
            {chains_list_items}
        </div>
        """

    legend_html = textwrap.dedent(f"""
    <div class="soc-legend-panel">
        <div class="soc-entity-header">
            <span class="soc-entity-title">🗺️ GRAPH LEGEND</span>
            {attack_status_badge}
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #9A968F; text-transform: uppercase; margin-bottom: 0.4rem; font-weight: 600; letter-spacing: 0.5px;">
            NODE TYPES
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.35rem;">
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #E63946;"></span>
                <span>Attack / Critical Target</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #00E5C7;"></span>
                <span>Host</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #F59E0B;"></span>
                <span>User</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #8A94A6;"></span>
                <span>File</span>
            </div>
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #9A968F; text-transform: uppercase; margin-top: 0.8rem; margin-bottom: 0.4rem; font-weight: 600; letter-spacing: 0.5px;">
            RELATIONSHIP TYPES
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.35rem;">
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #00E5C7;"></span>
                    <span>— Normal</span>
                </div>
                <span style="font-size: 0.65rem; color: #9A968F;">SMB / Auth</span>
            </div>
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #F59E0B; border-top: 2px dashed #F59E0B; height: 0;"></span>
                    <span>- - Suspicious</span>
                </div>
                <span style="font-size: 0.65rem; color: #F59E0B;">Unapproved</span>
            </div>
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #E63946; height: 3px;"></span>
                    <span style="color: #E63946; font-weight: 600;">➔ Attack Path</span>
                </div>
                <span style="font-size: 0.65rem; color: #E63946;">Pivot / Exfil</span>
            </div>
        </div>
        {chains_html}
    </div>
    """).strip()
    st.markdown(legend_html, unsafe_allow_html=True)


# -------------------------------------------------------------------------
# Main Attack Graph Renderer
# -------------------------------------------------------------------------
def render_attack_graph(
    graph_data: Optional[Dict[str, Any]] = None,
    height: int = 460,
    **kwargs
) -> None:
    """
    Renders the complete hybrid hierarchical attack-path command center workspace:
    1. Top Controls Bar (Filter, Highlight, Label Toggle, Inspect, Reset)
    2. Two-Column Main Visualization (Left: Legend, Right: Structured Hierarchical Canvas)
    3. Bottom Selected Entity Inspection Panel
    """
    # Initialize graph control states in Streamlit session state
    if "graph_selected_node_id" not in st.session_state:
        st.session_state["graph_selected_node_id"] = None

    if "graph_entity_filter" not in st.session_state:
        st.session_state["graph_entity_filter"] = "ALL"

    if "graph_show_labels" not in st.session_state:
        st.session_state["graph_show_labels"] = True

    if "graph_highlight_attack" not in st.session_state:
        st.session_state["graph_highlight_attack"] = False

    # 1. Section Header
    dataset_name = "Attack Topology"
    if graph_data:
        dataset_name = graph_data.get("name", graph_data.get("file_name", "Scenario Graph"))

    header_html = textwrap.dedent(f"""
    <div class="soc-section-header">
        <h3 class="soc-section-title">🌐 ATTACK PATH / HIERARCHICAL TOPOLOGY</h3>
        <span class="soc-section-subtitle">Target: {dataset_name} &bull; [ Structured Hierarchical Flow ]</span>
    </div>
    """).strip()
    st.markdown(header_html, unsafe_allow_html=True)

    # 2. Empty Graph Handling
    raw_nodes = graph_data.get("nodes", []) if graph_data else []
    raw_edges = graph_data.get("edges", []) if graph_data else []
    attack_chains = graph_data.get("attack_chains", []) if graph_data else []

    if not graph_data or (not raw_nodes and not raw_edges):
        empty_graph_html = textwrap.dedent("""
        <div class="soc-graph-container" style="min-height: 280px; justify-content: center; align-items: center;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #9A968F; text-align: center;">
                <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">🔍</span>
                No attack relationships available.
                <div style="font-size: 0.75rem; color: #5A6478; margin-top: 0.25rem;">
                    Ingest security logs or select an attack scenario above to generate network topology.
                </div>
            </div>
        </div>
        """).strip()
        st.markdown(empty_graph_html, unsafe_allow_html=True)
        return

    # Validate selected node ID against current dataset
    current_node_ids = {str(n.get("id", "")) for n in raw_nodes}
    if st.session_state["graph_selected_node_id"] and st.session_state["graph_selected_node_id"] not in current_node_ids:
        st.session_state["graph_selected_node_id"] = None

    # 3. Top Graph Controls Bar
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4, ctrl_col5 = st.columns([1.8, 1.4, 1.2, 2.2, 1.0])

    with ctrl_col1:
        # Entity Type Filter
        available_types = ["ALL"]
        for n in raw_nodes:
            t = str(n.get("type", "DEVICE")).upper()
            if t not in available_types:
                available_types.append(t)
        
        current_filter = st.session_state["graph_entity_filter"]
        filter_index = available_types.index(current_filter) if current_filter in available_types else 0
        
        selected_type = st.selectbox(
            "Filter Entity Type",
            options=available_types,
            index=filter_index,
            key="graph_filter_select",
            help="Filter graph to emphasize specific entity categories (User, Server, Device, etc.)"
        )
        st.session_state["graph_entity_filter"] = selected_type

    with ctrl_col2:
        # Highlight Attack Path Toggle
        highlight_attack = st.checkbox(
            "Highlight Attack Path",
            value=st.session_state["graph_highlight_attack"],
            key="graph_highlight_check",
            help="Visually emphasizes primary adversary attack chain with bold crimson directional lines"
        )
        st.session_state["graph_highlight_attack"] = highlight_attack

    with ctrl_col3:
        # Show/Hide Labels Toggle
        show_labels = st.checkbox(
            "Show Node Labels",
            value=st.session_state["graph_show_labels"],
            key="graph_labels_check",
            help="Toggle entity labels and protocol names on graph canvas"
        )
        st.session_state["graph_show_labels"] = show_labels

    with ctrl_col4:
        # Node Inspection Selector
        inspector_options = [("NONE", "Select Node to Inspect...")]
        for n in raw_nodes:
            n_id = str(n.get("id", ""))
            n_label = str(n.get("label", n_id))
            n_type = str(n.get("type", "")).upper()
            n_status = str(n.get("status", "")).upper()
            inspector_options.append((n_id, f"[{n_type}] {n_label} ({n_status})"))

        node_keys = [opt[0] for opt in inspector_options]
        current_node_sel = st.session_state["graph_selected_node_id"] or "NONE"
        sel_index = node_keys.index(current_node_sel) if current_node_sel in node_keys else 0

        selected_node_tuple_index = st.selectbox(
            "Inspect Entity",
            options=range(len(inspector_options)),
            format_func=lambda idx: inspector_options[idx][1],
            index=sel_index,
            key="graph_inspect_select",
            help="Choose a specific entity to inspect detailed telemetry, status, and risk"
        )
        chosen_node_id = inspector_options[selected_node_tuple_index][0]
        st.session_state["graph_selected_node_id"] = chosen_node_id if chosen_node_id != "NONE" else None

    with ctrl_col5:
        # Reset View Button
        st.markdown("<div style='height: 1.7rem;'></div>", unsafe_allow_html=True)
        if st.button("↺ Reset", key="graph_reset_btn", help="Reset graph filters, highlights, and selection"):
            st.session_state["graph_selected_node_id"] = None
            st.session_state["graph_entity_filter"] = "ALL"
            st.session_state["graph_show_labels"] = True
            st.session_state["graph_highlight_attack"] = False
            st.rerun()

    # 4. Filter Graph Nodes and Edges based on selected criteria
    active_filter = st.session_state["graph_entity_filter"]
    filtered_nodes = raw_nodes
    if active_filter != "ALL":
        filtered_nodes = [n for n in raw_nodes if str(n.get("type", "")).upper() == active_filter]

    filtered_node_ids = {str(n.get("id", "")) for n in filtered_nodes}
    filtered_edges = [
        e for e in raw_edges
        if str(e.get("source", e.get("from", ""))) in filtered_node_ids
        and str(e.get("target", e.get("to", ""))) in filtered_node_ids
    ] if active_filter != "ALL" else raw_edges

    visible_nodes_count = len(filtered_nodes)
    visible_edges_count = len(filtered_edges)

    # 5. Main Visualization Area: LEFT Column = Legend, RIGHT Column = Hierarchical Canvas
    main_col1, main_col2 = st.columns([1.0, 3.2])

    with main_col1:
        render_graph_legend_panel(attack_chains=attack_chains)

    with main_col2:
        # Hierarchical Canvas Header Strip
        strip_html = textwrap.dedent(f"""
        <div style="background: #080D16; border: 1px solid #162338; border-radius: 8px 8px 0 0; padding: 0.5rem 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: none;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #9A968F;">
                <span>TOPOLOGY: <strong style="color: #F5F2ED;">{dataset_name}</strong></span>
                <span style="margin: 0 8px; color: #162338;">|</span>
                <span>NODES: <strong style="color: #00E5C7;">{visible_nodes_count}</strong></span>
                <span style="margin: 0 8px; color: #162338;">|</span>
                <span>EDGES: <strong style="color: #00E5C7;">{visible_edges_count}</strong></span>
                <span style="margin: 0 8px; color: #162338;">|</span>
                <span>FILTER: <strong style="color: #38BDF8;">{active_filter}</strong></span>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #00E5C7;">
                ● HIERARCHICAL ATTACK FLOW
            </div>
        </div>
        """).strip()
        st.markdown(strip_html, unsafe_allow_html=True)

        # Render Hierarchical Interactive Canvas
        try:
            hierarchical_html = generate_hierarchical_graph_html(
                nodes=filtered_nodes,
                edges=filtered_edges,
                selected_node_id=st.session_state["graph_selected_node_id"],
                show_labels=st.session_state["graph_show_labels"],
                highlight_attack=st.session_state["graph_highlight_attack"],
                scenario_id=st.session_state.get("selected_scenario", "clean_logs"),
                height=height
            )
            components.html(hierarchical_html, height=height + 20, scrolling=False)
        except Exception as e:
            st.error(f"Unable to render hierarchical attack graph: {e}")

    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # 6. Bottom Selected Entity Inspection Panel
    selected_node_dict = None
    if st.session_state["graph_selected_node_id"]:
        for n in raw_nodes:
            if str(n.get("id", "")) == st.session_state["graph_selected_node_id"]:
                selected_node_dict = n
                break

    render_selected_entity_panel(selected_node=selected_node_dict)
