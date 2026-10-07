"""
Cyber Threat Command Center.
Main entrypoint and SOC dashboard orchestrator.

FRONTEND FOUNDATION & DATASET INTEGRATION:
- Session state initialization for data source & scenario switching
- Custom log ingestion (CSV, JSON, LOG, TXT)
- 3 One-click demo scenarios (Clean Logs, USB Exfiltration, Lateral Movement)
- Dynamic SOC operational metric cards
- Attack graph placeholder with dataset integration point
"""

import streamlit as st

# Import data and utilities
from data.demo_scenarios import get_demo_scenario
from components.styles import inject_soc_styles
from components.header import render_header
from components.dataset_controls import render_datasource_controls
from components.metric_cards import render_metric_cards
from components.graph_placeholder import render_graph_placeholder
from components.status_info import render_status_info

def initialize_session_state():
    """Initializes Streamlit session state variables with default baseline."""
    if "data_source" not in st.session_state:
        st.session_state["data_source"] = "demo"
    
    if "selected_scenario" not in st.session_state:
        st.session_state["selected_scenario"] = "clean_logs"

    if "dataset" not in st.session_state:
        st.session_state["dataset"] = get_demo_scenario("clean_logs")

    if "metrics" not in st.session_state:
        st.session_state["metrics"] = st.session_state["dataset"]["metrics"]

    if "uploaded_file_name" not in st.session_state:
        st.session_state["uploaded_file_name"] = None

    if "custom_dataset_result" not in st.session_state:
        st.session_state["custom_dataset_result"] = None

def main():
    # 1. Streamlit Page Configuration
    st.set_page_config(
        page_title="Cyber Threat Command Center",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # 2. Inject SOC Dark Theme Styling
    inject_soc_styles()

    # 3. Initialize Session State
    initialize_session_state()

    # 4. Render Main Header
    render_header(status_text="SYSTEM ONLINE")

    # 5. Render Data Source Controls (Demo Scenarios & Custom Log Ingestion)
    render_datasource_controls(
        current_source=st.session_state["data_source"],
        current_scenario_id=st.session_state["selected_scenario"],
        custom_dataset_info=st.session_state.get("custom_dataset_result")
    )

    st.markdown("<div style='height: 0.6rem;'></div>", unsafe_allow_html=True)

    # 6. Render Dynamic SOC Metric Cards
    render_metric_cards(metrics=st.session_state.get("metrics"))

    st.markdown("<div style='height: 0.6rem;'></div>", unsafe_allow_html=True)

    # 7. Render Attack Graph & Network Topology Container (Prepared for PyVis Integration)
    render_graph_placeholder(dataset=st.session_state.get("dataset"))

    st.markdown("<div style='height: 0.6rem;'></div>", unsafe_allow_html=True)

    # 8. Render Status & Information Telemetry
    render_status_info(dataset=st.session_state.get("dataset"))

if __name__ == "__main__":
    main()
