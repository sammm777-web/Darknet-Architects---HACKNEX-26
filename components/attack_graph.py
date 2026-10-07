"""
Interactive Attack Graph Component for SOC Command Center.
Uses PyVis (with vis.js WebGL/Canvas) and NetworkX to generate
an interactive force-directed attack path and network topology graph.
"""

import json
from typing import Dict, Any, Optional
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
        "width": 2.8,
        "dashes": False
    },
    "LATERAL MOVEMENT": {
        "color": "#f87171",
        "highlight": "#fca5a5",
        "hover": "#ef4444",
        "width": 3.0,
        "dashes": False
    },
    "EXFILTRATION": {
        "color": "#ec4899",
        "highlight": "#f472b6",
        "hover": "#db2777",
        "width": 3.0,
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

def create_pyvis_network(graph_data: Dict[str, Any], height: int = 500) -> Network:
    """
    Builds a styled PyVis Network instance from standardized graph data.
    """
    net = Network(
        height=f"{height}px",
        width="100%",
        bgcolor="#070b14",
        font_color="#e2e8f0",
        directed=True
    )

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    # Add Nodes
    for node in nodes:
        node_id = str(node.get("id", ""))
        label = str(node.get("label", node_id))
        category = str(node.get("type", "DEVICE")).upper()
        status = str(node.get("status", "SAFE")).upper()

        style = NODE_TYPE_STYLES.get(category, DEFAULT_NODE_STYLE).copy()
        
        # If node is a compromised server/host, tint border or background to indicate incident status
        node_color = style["color"].copy()
        if status == "COMPROMISED" and category not in ["ATTACKER"]:
            node_color["border"] = "#f87171"
        elif status == "MALICIOUS":
            node_color["background"] = "#ef4444"
            node_color["border"] = "#b91c1c"

        # Construct informative tooltip
        tooltip_lines = [
            f"<b>{label}</b>",
            f"Type: {category}",
            f"Status: {status}"
        ]
        for k, v in node.items():
            if k not in ["id", "label", "type", "status"]:
                tooltip_lines.append(f"{k.capitalize()}: {v}")
        title_html = "<br>".join(tooltip_lines)

        net.add_node(
            n_id=node_id,
            label=label,
            title=title_html,
            shape=style["shape"],
            size=style["size"],
            color=node_color,
            font=style["font"]
        )

    # Add Edges
    for edge in edges:
        source = str(edge.get("source", edge.get("from", "")))
        target = str(edge.get("target", edge.get("to", "")))
        edge_label = str(edge.get("label", ""))
        edge_type = str(edge.get("type", "ACCESS")).upper()
        edge_status = str(edge.get("status", "NORMAL")).upper()

        edge_style = EDGE_STATUS_COLORS.get(edge_status, EDGE_STATUS_COLORS.get(edge_type, EDGE_STATUS_COLORS["NORMAL"]))

        edge_color_dict = {
            "color": edge_style["color"],
            "highlight": edge_style["highlight"],
            "hover": edge_style["hover"]
        }

        net.add_edge(
            source=source,
            to=target,
            label=edge_label,
            title=f"Relationship: {edge_type}<br>Label: {edge_label}<br>Status: {edge_status}",
            color=edge_color_dict,
            width=edge_style["width"],
            dashes=edge_style["dashes"],
            arrows={"to": {"enabled": True, "scaleFactor": 0.75}}
        )

    # Configure physics for stable SOC network layout
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

def render_attack_graph(
    graph_data: Optional[Dict[str, Any]] = None,
    height: int = 520,
    **kwargs
) -> None:
    """
    Renders the interactive PyVis attack graph inside the SOC Command Center.
    
    Parameters:
    -----------
    graph_data : dict, optional
        Dictionary containing standardized 'nodes' and 'edges'.
    height : int
        Graph canvas viewport height in pixels.
    """
    # 1. Section Header
    dataset_name = "Attack Topology"
    if graph_data:
        dataset_name = graph_data.get("name", graph_data.get("file_name", "Scenario Graph"))

    header_html = f"""
    <div class="soc-section-header">
        <h3 class="soc-section-title">🌐 ATTACK PATH / NETWORK TOPOLOGY</h3>
        <span class="soc-section-subtitle">Target: {dataset_name} &bull; [ Interactive PyVis Engine ]</span>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)

    # 2. Empty Graph Handling
    if not graph_data or (not graph_data.get("nodes") and not graph_data.get("edges")):
        st.markdown(f"""
        <div class="soc-graph-container" style="min-height: 280px; justify-content: center; align-items: center;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #64748b; text-align: center;">
                <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">🔍</span>
                No attack relationships available.
                <div style="font-size: 0.75rem; color: #475569; margin-top: 0.25rem;">
                    Ingest security logs or select an attack scenario above to generate network topology.
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # 3. Graph Container Frame & Toolbar
    nodes_count = len(graph_data.get("nodes", []))
    edges_count = len(graph_data.get("edges", []))

    st.markdown(f"""
    <div style="background: #0c1322; border: 1px solid #1a263d; border-radius: 8px 8px 0 0; padding: 0.5rem 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: none;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #94a3b8;">
            <span>ACTIVE TOPOLOGY: <strong style="color: #ffffff;">{dataset_name}</strong></span>
            <span style="margin: 0 8px; color: #1e293b;">|</span>
            <span>NODES: <strong style="color: #38bdf8;">{nodes_count}</strong></span>
            <span style="margin: 0 8px; color: #1e293b;">|</span>
            <span>EDGES: <strong style="color: #38bdf8;">{edges_count}</strong></span>
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #34d399;">
            ● INTERACTIVE (Drag &bull; Zoom &bull; Pan)
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 4. Generate PyVis HTML
    try:
        net = create_pyvis_network(graph_data, height=height)
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
        # Graceful fallback if any rendering issue occurs
        st.error(f"Unable to render attack graph: {e}")

    # 5. Legend & Node Taxonomy Strip
    st.markdown("""
    <div style="display: flex; gap: 0.6rem; justify-content: center; flex-wrap: wrap; margin-top: 0.5rem; padding: 0.4rem; background: #090e1c; border: 1px solid #151f33; border-radius: 6px;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #f87171;">♦ Attacker</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #60a5fa;">■ Workstation</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #10b981;">⛃ Server</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #a855f7;">● User</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #f59e0b;">▤ File</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #eab308;">▲ USB</span>
        <span style="color: #1e293b;">|</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #f87171;">── Attack Vector</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #38bdf8;">── Normal Flow</span>
    </div>
    """, unsafe_allow_html=True)
