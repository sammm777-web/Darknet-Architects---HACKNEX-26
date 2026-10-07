"""
Status & Information Section Component.
Provides operational telemetry, pipeline health, and system readiness indicators.
"""

import streamlit as st

def render_status_info():
    """
    Renders the bottom system information and SOC operational telemetry section.
    """
    st.markdown('<div class="soc-section-title">🛡️ SYSTEM STATUS &amp; ENGINE TELEMETRY</div>', unsafe_allow_html=True)
    
    info_html = """
    <div class="soc-info-grid">
        <div class="soc-info-card">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #00e5ff; margin-bottom: 0.75rem;">
                PIPELINE STATUS &amp; CAPABILITIES
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Threat Ingestion Engine:</span>
                <span class="soc-info-val" style="color: #10b981;">STANDBY (Awaiting Data)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Graph Correlation Module:</span>
                <span class="soc-info-val" style="color: #94a3b8;">PyVis Engine (Unloaded)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Noise Filtering:</span>
                <span class="soc-info-val" style="color: #10b981;">Active (Heuristic + Rule-based)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Attack Graph Visualizer:</span>
                <span class="soc-info-val" style="color: #f59e0b;">Frontend Canvas Ready</span>
            </div>
        </div>
        <div class="soc-info-card">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #00e5ff; margin-bottom: 0.75rem;">
                SESSION TELEMETRY
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Interface Mode:</span>
                <span class="soc-info-val">SOC Command Center</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Target Viewport:</span>
                <span class="soc-info-val">1366px - 1920px (Desktop)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Environment:</span>
                <span class="soc-info-val" style="color: #10b981;">ONLINE</span>
            </div>
        </div>
    </div>
    """
    st.markdown(info_html, unsafe_allow_html=True)
