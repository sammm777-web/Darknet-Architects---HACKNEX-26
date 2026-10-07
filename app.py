"""
Interactive Security Operations Center (SOC) Command Center.
Main entrypoint and layout orchestrator.

FRONTEND FOUNDATION PHASE:
- Theme & Layout setup
- Command Center Header
- Data Source Selector & Ingestion Controls
- SOC Operational Metrics
- Attack Graph Visualizer Container Placeholder
- Operational Status & Telemetry
"""

import streamlit as st

# Import frontend components
from components.styles import inject_soc_styles
from components.header import render_header
from components.dataset_controls import render_datasource_controls
from components.metric_cards import render_metric_cards
from components.graph_placeholder import render_graph_placeholder
from components.status_info import render_status_info

def main():
    # 1. Streamlit Page Configuration
    st.set_page_config(
        page_title="Cyber Threat Command Center | Darknet Architects",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # 2. Inject SOC Dark Operations Center Styling
    inject_soc_styles()

    # 3. Render Header
    render_header(status_text="SYSTEM ONLINE")

    # 4. Render Data Source Section (Upload & Demo Scenarios Placeholders)
    render_datasource_controls()
    
    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # 5. Render SOC Operational Metric Cards
    # In future tasks, these values will be retrieved dynamically from st.session_state / backend engine
    current_metrics = {
        "total_logs": "12,482",
        "benign_logs": "11,973",
        "attack_chains": "03",
        "threat_level": "CRITICAL"
    }
    render_metric_cards(metrics=current_metrics)

    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # 6. Render Attack Graph & Network Topology Container
    render_graph_placeholder()

    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

    # 7. Render Status & Information Telemetry Section
    render_status_info()

if __name__ == "__main__":
    main()
