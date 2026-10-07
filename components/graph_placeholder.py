"""
Attack Graph Container & Placeholder Component.
Provides a central visual container for the attack path and network topology.
Easily replaced or extended with `render_attack_graph(...)` in future tasks.
"""

import streamlit as st

def render_graph_placeholder():
    """
    Renders the prominent central container where the interactive
    PyVis attack graph will be embedded.
    """
    st.markdown('<div class="soc-section-title">🌐 ATTACK PATH / NETWORK TOPOLOGY</div>', unsafe_allow_html=True)

    graph_container_html = """
    <div class="soc-graph-container">
        <div class="soc-graph-header">
            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #94a3b8;">
                VISUALIZATION CANVAS &bull; MITRE ATT&CK CORRELATION
            </span>
            <span class="soc-graph-slot-tag">
                [ PYVIS INTEGRATION SLOT ]
            </span>
        </div>
        <div class="soc-graph-canvas-placeholder">
            <div class="soc-graph-placeholder-icon">
                ⚡
            </div>
            <div class="soc-graph-placeholder-title">
                ATTACK PATH / NETWORK TOPOLOGY
            </div>
            <div class="soc-graph-placeholder-msg">
                Interactive attack graph will be rendered here.
                Node topologies, lateral movements, victim hosts, and C2 beacons will be visualized interactively.
            </div>
            <div style="display: flex; gap: 0.75rem; justify-content: center; flex-wrap: wrap;">
                <span style="font-size:0.75rem; color:#64748b; background: #070d18; padding: 4px 10px; border-radius: 4px; border: 1px solid #1e293b;">
                    🔵 Reconnaissance
                </span>
                <span style="font-size:0.75rem; color:#64748b; background: #070d18; padding: 4px 10px; border-radius: 4px; border: 1px solid #1e293b;">
                    🟠 Initial Access
                </span>
                <span style="font-size:0.75rem; color:#64748b; background: #070d18; padding: 4px 10px; border-radius: 4px; border: 1px solid #1e293b;">
                    🔴 Lateral Movement
                </span>
                <span style="font-size:0.75rem; color:#64748b; background: #070d18; padding: 4px 10px; border-radius: 4px; border: 1px solid #1e293b;">
                    🟣 Data Exfiltration
                </span>
            </div>
        </div>
    </div>
    """
    st.markdown(graph_container_html, unsafe_allow_html=True)
