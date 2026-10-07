"""
Main Header Component for SOC Command Center.
Renders title, subtitle, and system status indicator.
"""

import streamlit as st

def render_header(status_text: str = "SYSTEM ONLINE"):
    """
    Renders the compact SOC top navigation and command header.
    """
    header_html = f"""
    <div class="soc-header-container">
        <div class="soc-header-left">
            <h1 class="soc-header-title">
                CYBER THREAT COMMAND CENTER
                <span class="soc-header-badge">SOC v1.0</span>
            </h1>
            <p class="soc-header-subtitle">
                Interactive Security Operations &amp; Attack Path Analysis
            </p>
        </div>
        <div>
            <div class="soc-status-badge">
                <span class="soc-pulse-dot"></span>
                <span>{status_text}</span>
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)
