"""
SOC Metric Cards Component.
Displays high-level operational metrics:
- Total Logs Ingested
- Benign Logs Ignored
- Active Attack Chains
- Threat Level Assessment
"""

from typing import Dict, Any, Optional
import streamlit as st

DEFAULT_DEMO_METRICS: Dict[str, Any] = {
    "total_logs": "12,482",
    "benign_logs": "11,973",
    "attack_chains": "03",
    "threat_level": "CRITICAL"
}

def render_metric_cards(metrics: Optional[Dict[str, Any]] = None):
    """
    Renders the 4 standard SOC metric cards in a horizontal responsive grid.
    
    Parameters:
    -----------
    metrics : dict, optional
        Dictionary containing metric values:
        - total_logs: str or int
        - benign_logs: str or int
        - attack_chains: str or int
        - threat_level: str ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL")
    """
    if metrics is None:
        metrics = DEFAULT_DEMO_METRICS

    total_logs = metrics.get("total_logs", "0")
    benign_logs = metrics.get("benign_logs", "0")
    attack_chains = metrics.get("attack_chains", "0")
    threat_level = str(metrics.get("threat_level", "NORMAL")).upper()

    # Determine threat styling
    if threat_level in ["CRITICAL", "HIGH"]:
        threat_pill = f'<span class="soc-threat-pill-critical">{threat_level}</span>'
        threat_accent = "accent-crimson"
    elif threat_level == "MEDIUM":
        threat_pill = f'<span style="color:#f59e0b; font-weight:700; font-size:1.25rem;">{threat_level}</span>'
        threat_accent = "accent-amber"
    else:
        threat_pill = f'<span style="color:#10b981; font-weight:700; font-size:1.25rem;">{threat_level}</span>'
        threat_accent = "accent-cyan"

    cards_html = f"""
    <div class="soc-section-title">📊 SOC OPERATIONAL METRICS</div>
    <div class="soc-metric-grid">
        <div class="soc-metric-card accent-cyan">
            <div class="soc-metric-label">Total Logs Ingested</div>
            <div class="soc-metric-value">{total_logs}</div>
            <div class="soc-metric-meta">Processed event streams</div>
        </div>
        <div class="soc-metric-card accent-blue">
            <div class="soc-metric-label">Benign Logs Ignored</div>
            <div class="soc-metric-value">{benign_logs}</div>
            <div class="soc-metric-meta">Noise reduction ratio: 95.9%</div>
        </div>
        <div class="soc-metric-card accent-amber">
            <div class="soc-metric-label">Active Attack Chains</div>
            <div class="soc-metric-value">{attack_chains}</div>
            <div class="soc-metric-meta">Correlated threat vectors</div>
        </div>
        <div class="soc-metric-card {threat_accent}">
            <div class="soc-metric-label">Threat Level</div>
            <div class="soc-metric-value" style="padding-top:2px;">{threat_pill}</div>
            <div class="soc-metric-meta">Automated triage status</div>
        </div>
    </div>
    """
    st.markdown(cards_html, unsafe_allow_html=True)
