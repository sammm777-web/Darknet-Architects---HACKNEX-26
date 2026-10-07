"""
Status & Information Section Component.
Provides operational telemetry, pipeline readiness, and system health status.
"""

from typing import Dict, Any, Optional
import streamlit as st

def render_status_info(dataset: Optional[Dict[str, Any]] = None, **kwargs):
    """
    Renders the bottom system telemetry and SOC operational status.
    """
    st.markdown("""
    <div class="soc-section-header">
        <h3 class="soc-section-title">🛡️ SYSTEM STATUS &amp; PIPELINE TELEMETRY</h3>
        <span class="soc-section-subtitle">Subsystem readiness &amp; interface health</span>
    </div>
    """, unsafe_allow_html=True)
    
    info_html = """
    <div class="soc-info-grid">
        <div class="soc-info-card">
            <div class="soc-info-header">
                <span>PIPELINE SUBSYSTEMS</span>
                <span style="color: #34d399; font-size: 0.7rem;">● OPERATIONAL</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Log Ingestion:</span>
                <span class="soc-info-val" style="color: #34d399;">Active (CSV, JSON, LOG, TXT)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Noise Filtering:</span>
                <span class="soc-info-val" style="color: #34d399;">Enabled (Rule-based noise reduction)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Graph Engine:</span>
                <span class="soc-info-val" style="color: #60a5fa;">Canvas Container Mounted (PyVis Slot)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Threat Classifier:</span>
                <span class="soc-info-val" style="color: #94a3b8;">Ready for Backend Integration</span>
            </div>
        </div>
        <div class="soc-info-card">
            <div class="soc-info-header">
                <span>SESSION TELEMETRY</span>
                <span style="color: #38bdf8; font-size: 0.7rem;">LOCAL</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Interface Mode:</span>
                <span class="soc-info-val">Enterprise SOC Command</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Display Mode:</span>
                <span class="soc-info-val">Desktop / Projector (1366px+)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Session Health:</span>
                <span class="soc-info-val" style="color: #34d399;">● Connected</span>
            </div>
        </div>
    </div>
    """
    st.markdown(info_html, unsafe_allow_html=True)
