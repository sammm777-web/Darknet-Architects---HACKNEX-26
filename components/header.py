"""
Main Header Component for SOC Command Center.
Renders title, subtitle, and DEFCON/System status indicator with sleek enterprise styling.
"""

import textwrap
import streamlit as st

def render_header(status_text: str = "DEFCON 4 // ACTIVE MONITORING", is_alert: bool = True, **kwargs):
    """
    Renders the enterprise SOC top header with DEFCON status and pulsing glow.
    """
    badge_class = "soc-defcon-badge" if is_alert else "soc-defcon-badge online"
    pulse_dot_class = "soc-pulse-dot-red" if is_alert else "soc-pulse-dot-teal"

    header_html = textwrap.dedent(f"""
    <div class="soc-header-container">
        <div class="soc-header-left">
            <div class="soc-header-title-row">
                <h1 class="soc-header-title">CYBER THREAT COMMAND CENTER</h1>
                <span class="soc-header-badge">SOC v2.0</span>
            </div>
            <p class="soc-header-subtitle">
                Interactive Security Operations &amp; Attack Path Analysis
            </p>
        </div>
        <div class="soc-header-right">
            <div class="{badge_class}">
                <span class="{pulse_dot_class}"></span>
                <span>{status_text}</span>
            </div>
        </div>
    </div>
    """).strip()
    st.markdown(header_html, unsafe_allow_html=True)
