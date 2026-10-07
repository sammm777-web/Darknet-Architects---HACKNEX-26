"""
Main Header Component for SOC Command Center.
Renders title, subtitle, and system status indicator with clean enterprise styling.
"""

import streamlit as st

def render_header(status_text: str = "SYSTEM ONLINE", **kwargs):
    """
    Renders the clean enterprise SOC top header.
    """
    header_html = f"""
    <div class="soc-header-container">
        <div class="soc-header-left">
            <div class="soc-header-title-row">
                <h1 class="soc-header-title">CYBER THREAT COMMAND CENTER</h1>
                <span class="soc-header-badge">SOC v1.2</span>
            </div>
            <p class="soc-header-subtitle">
                Interactive Security Operations &amp; Attack Path Analysis
            </p>
        </div>
        <div class="soc-header-right">
            <div class="soc-status-badge">
                <span class="soc-pulse-dot"></span>
                <span>{status_text}</span>
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)
