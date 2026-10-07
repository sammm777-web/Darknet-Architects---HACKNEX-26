"""
Status & Information Section Component.
Provides operational telemetry, pipeline readiness, and system health status.
"""

from typing import Dict, Any, Optional
import textwrap
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
    
    info_html = textwrap.dedent("""
    <div class="soc-info-grid">
        <div class="soc-info-card">
            <div class="soc-info-header">
                <span>PIPELINE SUBSYSTEMS</span>
                <span style="color: #9A968F; font-size: 0.7rem;">● OPERATIONAL</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Log Ingestion:</span>
                <span class="soc-info-val" style="color: #F5F2ED;">Active (CSV, JSON, LOG, TXT)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Noise Filtering:</span>
                <span class="soc-info-val" style="color: #F5F2ED;">Enabled (Rule-based reduction)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Graph Engine:</span>
                <span class="soc-info-val" style="color: #9A968F;">Canvas Mounted (PyVis Slot)</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Threat Classifier:</span>
                <span class="soc-info-val" style="color: #9A968F;">Ready for Backend Integration</span>
            </div>
        </div>
        <div class="soc-info-card">
            <div class="soc-info-header">
                <span>SESSION TELEMETRY</span>
                <span style="color: #9A968F; font-size: 0.7rem;">LOCAL</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Interface Mode:</span>
                <span class="soc-info-val">Enterprise SOC Command</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Display Mode:</span>
                <span class="soc-info-val">Desktop / Presentation</span>
            </div>
            <div class="soc-info-row">
                <span class="soc-info-key">Session Health:</span>
                <span class="soc-info-val" style="color: #F5F2ED;">● Connected</span>
            </div>
        </div>
    </div>
    """).strip()
    st.markdown(info_html, unsafe_allow_html=True)
