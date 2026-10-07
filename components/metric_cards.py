"""
SOC Metric Cards Component.
Displays dynamic high-level operational telemetry cards:
- Total Logs Ingested
- Benign Logs Ignored
- Active Attack Chains
- Threat Level Assessment
"""

from typing import Dict, Any, Optional
import textwrap
import streamlit as st

DEFAULT_METRICS: Dict[str, Any] = {
    "total_logs": "1,240",
    "benign_logs": "1,240",
    "attack_chains": "0",
    "threat_level": "LOW"
}

def render_metric_cards(metrics: Optional[Dict[str, Any]] = None, **kwargs):
    """
    Renders the 4 standard SOC metric cards in a responsive grid.
    """
    if metrics is None:
        metrics = DEFAULT_METRICS

    total_logs = str(metrics.get("total_logs", "0"))
    benign_logs = str(metrics.get("benign_logs", "0"))
    attack_chains = str(metrics.get("attack_chains", "0"))
    threat_level = str(metrics.get("threat_level", "LOW")).upper()

    # Determine threat styling
    if threat_level == "CRITICAL":
        threat_pill = '<span class="soc-threat-pill critical">CRITICAL</span>'
        threat_accent = "accent-crimson"
        threat_subtext = "Immediate response required"
    elif threat_level == "HIGH":
        threat_pill = '<span class="soc-threat-pill high">HIGH</span>'
        threat_accent = "accent-amber"
        threat_subtext = "Active incident triaged"
    elif threat_level in ["EVALUATING", "ANALYZING", "PENDING"]:
        threat_pill = f'<span class="soc-threat-pill analyzing">{threat_level}</span>'
        threat_accent = "accent-teal"
        threat_subtext = "Detection pipeline queued"
    else:
        threat_pill = '<span class="soc-threat-pill low">LOW</span>'
        threat_accent = "accent-teal"
        threat_subtext = "Baseline within normal limits"

    cards_html = textwrap.dedent(f"""
    <div class="soc-section-header">
        <h3 class="soc-section-title">📊 SOC METRICS</h3>
        <span class="soc-section-subtitle">Real-time incident response &amp; log reduction metrics</span>
    </div>
    <div class="soc-metric-grid">
        <div class="soc-metric-card accent-teal">
            <div class="soc-metric-label">Total Logs Ingested</div>
            <div class="soc-metric-value">{total_logs}</div>
            <div class="soc-metric-subtext">Ingested stream events</div>
        </div>
        <div class="soc-metric-card accent-blue">
            <div class="soc-metric-label">Benign Logs Ignored</div>
            <div class="soc-metric-value">{benign_logs}</div>
            <div class="soc-metric-subtext">Filtered background noise</div>
        </div>
        <div class="soc-metric-card accent-amber">
            <div class="soc-metric-label">Active Attack Chains</div>
            <div class="soc-metric-value">{attack_chains}</div>
            <div class="soc-metric-subtext">Correlated kill chains</div>
        </div>
        <div class="soc-metric-card {threat_accent}">
            <div class="soc-metric-label">Threat Level</div>
            <div class="soc-metric-value" style="font-size: 1.35rem; padding-top: 2px;">{threat_pill}</div>
            <div class="soc-metric-subtext">{threat_subtext}</div>
        </div>
    </div>
    """).strip()
    st.markdown(cards_html, unsafe_allow_html=True)
