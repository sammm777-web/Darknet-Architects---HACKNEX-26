"""
Interactive Attack Graph Component for SOC Command Center.
Uses PyVis (with vis.js WebGL/Canvas) and NetworkX to generate
an interactive force-directed attack path and network topology graph.

Provides:
1. Responsive PyVis canvas with physics stabilization, pan, zoom, drag
2. Graph controls (Reset View, Show/Hide Labels, Entity Type Filter, Highlight Attack Path)
3. Node inspection & selected entity information card
4. Comprehensive SOC graph legend & attack chain summary
5. Attack-path visual highlighting (adversary kill-chain vs benign traffic)
"""

import json
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
# Node Styling Configuration by Category
# -------------------------------------------------------------------------
NODE_TYPE_STYLES: Dict[str, Dict[str, Any]] = {
    "ATTACKER": {
        "color": {
            "background": "#ef4444",
            "border": "#b91c1c",
            "highlight": {"background": "#f87171", "border": "#dc2626"},
            "hover": {"background": "#dc2626", "border": "#991b1b"}
        },
        "shape": "diamond",
        "size": 28,
        "font": {"color": "#ffffff", "size": 13, "face": "Inter, monospace", "bold": True}
    },
    "IP": {
        "color": {
            "background": "#38bdf8",
            "border": "#0284c7",
            "highlight": {"background": "#7dd3fc", "border": "#0369a1"},
            "hover": {"background": "#0ea5e9", "border": "#075985"}
        },
        "shape": "dot",
        "size": 22,
        "font": {"color": "#e2e8f0", "size": 12, "face": "Inter, monospace"}
    },
    "USER": {
        "color": {
            "background": "#a855f7",
            "border": "#7e22ce",
            "highlight": {"background": "#c084fc", "border": "#6b21a8"},
            "hover": {"background": "#9333ea", "border": "#581c87"}
        },
        "shape": "ellipse",
        "size": 24,
        "font": {"color": "#ffffff", "size": 12, "face": "Inter, monospace"}
    },
    "DEVICE": {
        "color": {
            "background": "#3b82f6",
            "border": "#1d4ed8",
            "highlight": {"background": "#60a5fa", "border": "#1e40af"},
            "hover": {"background": "#2563eb", "border": "#172554"}
        },
        "shape": "box",
        "size": 24,
        "font": {"color": "#ffffff", "size": 12, "face": "Inter, monospace"}
    },
    "SERVER": {
        "color": {
            "background": "#10b981",
            "border": "#047857",
            "highlight": {"background": "#34d399", "border": "#065f46"},
            "hover": {"background": "#059669", "border": "#022c22"}
        },
        "shape": "database",
        "size": 26,
        "font": {"color": "#ffffff", "size": 12, "face": "Inter, monospace"}
    },
    "FILE": {
        "color": {
            "background": "#f59e0b",
            "border": "#b45309",
            "highlight": {"background": "#fbbf24", "border": "#92400e"},
            "hover": {"background": "#d97706", "border": "#78350f"}
        },
        "shape": "box",
        "size": 20,
        "font": {"color": "#ffffff", "size": 11, "face": "Inter, monospace"}
    },
    "USB DEVICE": {
        "color": {
            "background": "#eab308",
            "border": "#a16207",
            "highlight": {"background": "#fde047", "border": "#854d0e"},
            "hover": {"background": "#ca8a04", "border": "#713f12"}
        },
        "shape": "triangle",
        "size": 24,
        "font": {"color": "#ffffff", "size": 12, "face": "Inter, monospace"}
    },
    "USB": {
        "color": {
            "background": "#eab308",
            "border": "#a16207",
            "highlight": {"background": "#fde047", "border": "#854d0e"},
            "hover": {"background": "#ca8a04", "border": "#713f12"}
        },
        "shape": "triangle",
        "size": 24,
        "font": {"color": "#ffffff", "size": 12, "face": "Inter, monospace"}
    }
}

DEFAULT_NODE_STYLE = {
    "color": {
        "background": "#64748b",
        "border": "#334155",
        "highlight": {"background": "#94a3b8", "border": "#475569"},
        "hover": {"background": "#475569", "border": "#1e293b"}
    },
    "shape": "dot",
    "size": 20,
    "font": {"color": "#e2e8f0", "size": 12, "face": "Inter, monospace"}
}

# -------------------------------------------------------------------------
# Edge Styling Configuration
# -------------------------------------------------------------------------
EDGE_STATUS_COLORS: Dict[str, Dict[str, Any]] = {
    "ATTACK": {
        "color": "#ef4444",
        "highlight": "#f87171",
        "hover": "#dc2626",
        "width": 3.2,
        "dashes": False
    },
    "LATERAL MOVEMENT": {
        "color": "#f87171",
        "highlight": "#fca5a5",
        "hover": "#ef4444",
        "width": 3.2,
        "dashes": False
    },
    "EXFILTRATION": {
        "color": "#ec4899",
        "highlight": "#f472b6",
        "hover": "#db2777",
        "width": 3.2,
        "dashes": True
    },
    "SUSPICIOUS": {
        "color": "#f59e0b",
        "highlight": "#fbbf24",
        "hover": "#d97706",
        "width": 2.2,
        "dashes": True
    },
    "BENIGN": {
        "color": "#38bdf8",
        "highlight": "#7dd3fc",
        "hover": "#0ea5e9",
        "width": 1.4,
        "dashes": False
    },
    "NORMAL": {
        "color": "#64748b",
        "highlight": "#94a3b8",
        "hover": "#475569",
        "width": 1.4,
        "dashes": False
    }
}


def create_pyvis_network(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    selected_node_id: Optional[str] = None,
    show_labels: bool = True,
    highlight_attack: bool = False,
    height: int = 500
) -> Network:
    """
    Builds a styled PyVis Network instance from filtered nodes and edges.
    """
    net = Network(
        height=f"{height}px",
        width="100%",
        bgcolor="#070b14",
        font_color="#e2e8f0",
        directed=True
    )

    # 1. Add Nodes
    for node in nodes:
        node_id = str(node.get("id", ""))
        raw_label = str(node.get("label", node_id))
        category = str(node.get("type", "DEVICE")).upper()
        status = str(node.get("status", "SAFE")).upper()
        risk = str(node.get("risk", "LOW")).upper()

        style = NODE_TYPE_STYLES.get(category, DEFAULT_NODE_STYLE).copy()
        node_color = style["color"].copy()
        node_size = style["size"]

        # If node is compromised / malicious
        if status in ["COMPROMISED", "TARGET"] and category not in ["ATTACKER"]:
            node_color["border"] = "#f87171"
            if highlight_attack:
                node_color["background"] = "#991b1b"
        elif status == "MALICIOUS":
            node_color["background"] = "#ef4444"
            node_color["border"] = "#b91c1c"

        # If this is the actively selected node in inspector
        if selected_node_id and node_id == selected_node_id:
            node_size = int(node_size * 1.35)
            node_color["border"] = "#38bdf8"
            node_color["background"] = "#0284c7" if category != "ATTACKER" else "#dc2626"

        # Node label toggle
        display_label = raw_label if show_labels else " "

        # Construct informative tooltip
        tooltip_lines = [
            f"<b>{raw_label}</b>",
            f"Type: {category}",
            f"Status: {status}",
            f"Risk: {risk}"
        ]
        for k, v in node.items():
            if k not in ["id", "label", "type", "status", "risk"]:
                tooltip_lines.append(f"{k.capitalize()}: {v}")
        title_html = "<br>".join(tooltip_lines)

        net.add_node(
            n_id=node_id,
            label=display_label,
            title=title_html,
            shape=style["shape"],
            size=node_size,
            color=node_color,
            font=style["font"]
        )

    # 2. Add Edges
    for edge in edges:
        source = str(edge.get("source", edge.get("from", "")))
        target = str(edge.get("target", edge.get("to", "")))
        edge_label = str(edge.get("label", ""))
        edge_type = str(edge.get("type", "ACCESS")).upper()
        edge_status = str(edge.get("status", "NORMAL")).upper()

        edge_style = EDGE_STATUS_COLORS.get(edge_status, EDGE_STATUS_COLORS.get(edge_type, EDGE_STATUS_COLORS["NORMAL"]))

        edge_color = edge_style["color"]
        edge_width = edge_style["width"]
        edge_dashes = edge_style["dashes"]

        # Attack path emphasis
        is_attack_edge = edge_status in ["ATTACK", "LATERAL MOVEMENT", "EXFILTRATION"] or edge_type in ["LATERAL MOVEMENT", "EXFILTRATION"]

        if highlight_attack:
            if is_attack_edge:
                edge_color = "#ef4444"
                edge_width = 3.6
            else:
                edge_color = "#1e293b"
                edge_width = 1.0

        edge_color_dict = {
            "color": edge_color,
            "highlight": "#f87171" if is_attack_edge else "#38bdf8",
            "hover": "#dc2626" if is_attack_edge else "#0ea5e9"
        }

        display_edge_label = edge_label if show_labels else ""

        net.add_edge(
            source=source,
            to=target,
            label=display_edge_label,
            title=f"Relationship: {edge_type}<br>Detail: {edge_label}<br>Status: {edge_status}",
            color=edge_color_dict,
            width=edge_width,
            dashes=edge_dashes,
            arrows={"to": {"enabled": True, "scaleFactor": 0.8}}
        )

    # Physics and interaction configuration
    options = {
        "nodes": {
            "borderWidth": 2,
            "shadow": {"enabled": True, "color": "rgba(0,0,0,0.5)", "size": 6, "x": 2, "y": 2}
        },
        "edges": {
            "smooth": {"type": "continuous", "roundness": 0.25},
            "font": {
                "size": 11,
                "face": "JetBrains Mono, monospace",
                "color": "#94a3b8",
                "strokeWidth": 2,
                "strokeColor": "#070b14",
                "align": "horizontal"
            }
        },
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -55,
                "centralGravity": 0.015,
                "springLength": 120,
                "springConstant": 0.08,
                "damping": 0.4
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 150}
        },
        "interaction": {
            "hover": True,
            "zoomView": True,
            "dragView": True,
            "dragNodes": True,
            "navigationButtons": False,
            "tooltipDelay": 100
        }
    }

    net.set_options(json.dumps(options))
    return net


import textwrap

def render_selected_entity_panel(selected_node: Optional[Dict[str, Any]]) -> None:
    """
    Renders the SELECTED ENTITY inspection card.
    """
    if not selected_node:
        empty_html = textwrap.dedent("""
        <div class="soc-entity-panel">
            <div class="soc-entity-header">
                <span class="soc-entity-title">🔍 SELECTED ENTITY</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #64748b;">STANDBY</span>
            </div>
            <div class="soc-entity-empty">
                <span style="font-size: 1.5rem; margin-bottom: 0.4rem;">🎯</span>
                <div><strong>No entity selected.</strong></div>
                <div style="font-size: 0.74rem; color: #475569; margin-top: 0.25rem;">
                    Select any entity from the inspection control above or hover on graph nodes.
                </div>
            </div>
        </div>
        """).strip()
        st.markdown(empty_html, unsafe_allow_html=True)
        return

    # Extract clean standardized metadata
    label = selected_node.get("label", selected_node.get("id", "Unknown"))
    entity_type = str(selected_node.get("type", "UNKNOWN")).upper()
    status = str(selected_node.get("status", "ACTIVE")).upper()
    risk = str(selected_node.get("risk", "LOW")).upper()
    ip_addr = selected_node.get("ip", "N/A")
    device_name = selected_node.get("device", selected_node.get("os", "N/A"))
    first_seen = selected_node.get("first_seen", "00:00:00")
    last_activity = selected_node.get("last_activity", "00:00:00")

    # Risk badge styling
    risk_badge_class = "soc-badge-low"
    if risk == "CRITICAL":
        risk_badge_class = "soc-badge-critical"
    elif risk in ["HIGH", "MEDIUM"]:
        risk_badge_class = "soc-badge-high"

    # Status badge styling
    status_color = "#34d399"
    if status in ["COMPROMISED", "MALICIOUS"]:
        status_color = "#f87171"
    elif status in ["SUSPICIOUS", "TARGET"]:
        status_color = "#fbbf24"

    # Additional contextual fields
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
            <span class="soc-entity-title">🔍 SELECTED ENTITY: <strong style="color: #38bdf8;">{label}</strong></span>
            <div style="display: flex; gap: 0.4rem; align-items: center;">
                <span class="soc-scenario-badge {risk_badge_class}">RISK: {risk}</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; font-weight: 600; padding: 1px 6px; border-radius: 3px; background: rgba(239, 68, 68, 0.1); color: {status_color}; border: 1px solid rgba(255,255,255,0.08);">
                    {status}
                </span>
            </div>
        </div>
        <div class="soc-entity-grid">
            <div class="soc-entity-cell">
                <div class="soc-entity-key">Entity Label</div>
                <div class="soc-entity-val" style="color: #38bdf8;">{label}</div>
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


def render_graph_legend_panel(attack_chains: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Renders the compact SOC graph legend and active attack chain summary.
    """
    chains_count = len(attack_chains) if attack_chains else 0
    attack_status_badge = f"""<span style="color: #f87171; font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; font-weight: 600;">ACTIVE CHAINS: {chains_count}</span>""" if chains_count > 0 else """<span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; font-weight: 600;">BASELINE SAFE</span>"""

    chains_html = ""
    if attack_chains:
        chains_list_items = ""
        for chain in attack_chains:
            chain_name = chain.get("name", "Malicious Chain")
            chain_ttp = chain.get("ttp", "")
            chain_status = chain.get("status", "Active")
            ttp_badge = f"""<span style="color: #fbbf24; font-size: 0.65rem; margin-left: 4px;">[{chain_ttp}]</span>""" if chain_ttp else ""
            chains_list_items += f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; padding: 0.25rem 0; border-bottom: 1px solid #151f33; display: flex; justify-content: space-between;">
                <span>⚠️ {chain_name} {ttp_badge}</span>
                <span style="color: #f87171; font-size: 0.68rem;">{chain_status}</span>
            </div>
            """
        chains_html = f"""
        <div style="margin-top: 0.75rem; padding-top: 0.5rem; border-top: 1px solid #1a263d;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.35rem;">
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
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.3rem;">
            Node Entity Types
        </div>
        <div class="soc-legend-grid">
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #ef4444;"></span>
                <span>Attacker</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #38bdf8;"></span>
                <span>IP Address</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #a855f7;"></span>
                <span>User</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #3b82f6;"></span>
                <span>Device</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #10b981;"></span>
                <span>Server</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #f59e0b;"></span>
                <span>File</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #eab308;"></span>
                <span>USB Device</span>
            </div>
            <div class="soc-legend-item-box">
                <span class="soc-legend-dot" style="background: #64748b;"></span>
                <span>Infrastructure</span>
            </div>
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #94a3b8; text-transform: uppercase; margin-top: 0.65rem; margin-bottom: 0.3rem;">
            Relationship Types
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.35rem;">
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #38bdf8;"></span>
                    <span>Normal relationship</span>
                </div>
                <span style="font-size: 0.65rem; color: #64748b;">Kerberos / SMB / Login</span>
            </div>
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #f59e0b; border-style: dashed;"></span>
                    <span>Suspicious relationship</span>
                </div>
                <span style="font-size: 0.65rem; color: #f59e0b;">Unapproved Access</span>
            </div>
            <div class="soc-legend-item-box" style="justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="soc-legend-line" style="background: #ef4444; height: 4px;"></span>
                    <span style="color: #f87171; font-weight: 600;">Attack path</span>
                </div>
                <span style="font-size: 0.65rem; color: #f87171;">C2 / Pivot / Exfil</span>
            </div>
        </div>
        {chains_html}
    </div>
    """).strip()
    st.markdown(legend_html, unsafe_allow_html=True)


def render_attack_graph(
    graph_data: Optional[Dict[str, Any]] = None,
    height: int = 500,
    **kwargs
) -> None:
    """
    Renders the complete interactive attack graph workspace including:
    - Graph Controls Toolbar
    - Interactive PyVis Canvas
    - Selected Entity Inspection Panel
    - Graph Legend and Attack Path Telemetry
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
        <h3 class="soc-section-title">🌐 ATTACK PATH / NETWORK TOPOLOGY</h3>
        <span class="soc-section-subtitle">Target: {dataset_name} &bull; [ Interactive PyVis Engine ]</span>
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
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #64748b; text-align: center;">
                <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">🔍</span>
                No attack relationships available.
                <div style="font-size: 0.75rem; color: #475569; margin-top: 0.25rem;">
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

    # 3. Graph Controls Bar
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
            help="Visually emphasizes primary adversary attack chain with bold directional lines"
        )
        st.session_state["graph_highlight_attack"] = highlight_attack

    with ctrl_col3:
        # Show/Hide Labels Toggle
        show_labels = st.checkbox(
            "Show Node Labels",
            value=st.session_state["graph_show_labels"],
            key="graph_labels_check",
            help="Toggle entity labels visibility on graph canvas"
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

    # 5. Graph Container Header Strip
    visible_nodes_count = len(filtered_nodes)
    visible_edges_count = len(filtered_edges)

    strip_html = textwrap.dedent(f"""
    <div style="background: #0c1322; border: 1px solid #1a263d; border-radius: 8px 8px 0 0; padding: 0.5rem 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: none; margin-top: 0.5rem;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #94a3b8;">
            <span>TOPOLOGY: <strong style="color: #ffffff;">{dataset_name}</strong></span>
            <span style="margin: 0 8px; color: #1e293b;">|</span>
            <span>NODES: <strong style="color: #38bdf8;">{visible_nodes_count}</strong></span>
            <span style="margin: 0 8px; color: #1e293b;">|</span>
            <span>EDGES: <strong style="color: #38bdf8;">{visible_edges_count}</strong></span>
            <span style="margin: 0 8px; color: #1e293b;">|</span>
            <span>FILTER: <strong style="color: #a855f7;">{active_filter}</strong></span>
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #34d399;">
            ● INTERACTIVE CANVAS (Drag &bull; Zoom &bull; Pan &bull; Hover)
        </div>
    </div>
    """).strip()
    st.markdown(strip_html, unsafe_allow_html=True)

    # 6. Render PyVis Canvas
    try:
        net = create_pyvis_network(
            nodes=filtered_nodes,
            edges=filtered_edges,
            selected_node_id=st.session_state["graph_selected_node_id"],
            show_labels=st.session_state["graph_show_labels"],
            highlight_attack=st.session_state["graph_highlight_attack"],
            height=height
        )
        raw_html = net.generate_html()

        # Custom inline style injection for full container fit
        custom_wrapper = f"""
        <style>
            html, body {{
                margin: 0;
                padding: 0;
                background-color: #070b14 !important;
                overflow: hidden;
            }}
            #mynetwork {{
                background-color: #070b14 !important;
                border: 1px solid #1a263d !important;
                border-radius: 0 0 8px 8px;
            }}
        </style>
        {raw_html}
        """

        components.html(custom_wrapper, height=height + 20, scrolling=False)

    except Exception as e:
        st.error(f"Unable to render attack graph: {e}")

    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # 7. Bottom Two-Column Inspector & Legend Layout
    # Find active node dict if any
    selected_node_dict = None
    if st.session_state["graph_selected_node_id"]:
        for n in raw_nodes:
            if str(n.get("id", "")) == st.session_state["graph_selected_node_id"]:
                selected_node_dict = n
                break

    bottom_col1, bottom_col2 = st.columns([1.3, 1.0])

    with bottom_col1:
        render_selected_entity_panel(selected_node=selected_node_dict)

    with bottom_col2:
        render_graph_legend_panel(attack_chains=attack_chains)
