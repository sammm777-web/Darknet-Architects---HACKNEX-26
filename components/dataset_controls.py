"""
Data Source & Scenario Selection Component.
Handles custom log uploads (CSV, JSON, TXT, LOG), demo scenario toggling,
and validation state tracking for the SOC dashboard.
"""

from typing import Dict, Any, Optional
import streamlit as st
from data.demo_scenarios import DEMO_SCENARIOS, get_demo_scenario
from utils.data_loader import load_dataset

def render_datasource_controls(
    current_source: Optional[str] = None,
    current_scenario_id: Optional[str] = None,
    custom_dataset_info: Optional[Dict[str, Any]] = None,
    **kwargs
) -> None:
    """
    Renders the interactive Data Source controls:
    1. Active Dataset Status Banner
    2. Demo Scenario Selection Buttons
    3. Custom Log File Ingestion Uploader
    """
    # Safe session state fallbacks
    if current_source is None:
        current_source = st.session_state.get("data_source", "demo")
    if current_scenario_id is None:
        current_scenario_id = st.session_state.get("selected_scenario", "clean_logs")
    if custom_dataset_info is None:
        custom_dataset_info = st.session_state.get("custom_dataset_result")

    # 1. Dataset Status Banner
    if current_source == "custom" and custom_dataset_info and custom_dataset_info.get("status") == "success":
        source_label = f"CUSTOM DATASET — {custom_dataset_info.get('file_name', 'Uploaded File')}"
        source_badge = '<span class="soc-source-tag custom">CUSTOM FILE</span>'
        log_count_str = f"{custom_dataset_info.get('total_logs', 0):,}"
    else:
        active_scenario = get_demo_scenario(current_scenario_id)
        source_label = f"DEMO SCENARIO — {active_scenario['name'].upper()}"
        source_badge = '<span class="soc-source-tag demo">DEMO PRESET</span>'
        log_count_str = active_scenario["metrics"]["total_logs"]

    status_strip_html = f"""
    <div class="soc-active-source-strip">
        <div class="soc-source-indicator">
            <span style="color: #38bdf8;">●</span>
            <span style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase;">Active Data Source:</span>
            <span style="color: #ffffff; font-weight: 600;">{source_label}</span>
            {source_badge}
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
            <span style="color: #64748b;">LOGS INGESTED: </span>
            <span style="color: #38bdf8; font-weight: 700;">{log_count_str}</span>
        </div>
    </div>
    """
    st.markdown(status_strip_html, unsafe_allow_html=True)

    # 2. Main Data Source Container
    st.markdown("""
    <div class="soc-section-header">
        <h3 class="soc-section-title">📂 DATA SOURCE</h3>
        <span class="soc-section-subtitle">Select a pre-configured attack scenario or ingest custom logs</span>
    </div>
    """, unsafe_allow_html=True)

    col_scenarios, col_upload = st.columns([1.5, 1], gap="large")

    # Left Column: Demo Scenarios
    with col_scenarios:
        st.markdown("<div style='font-size:0.78rem; font-weight:600; color:#cbd5e1; margin-bottom:0.5rem;'>PRELOADED DEMO SCENARIOS</div>", unsafe_allow_html=True)
        
        btn_col0, btn_col1, btn_col2 = st.columns(3, gap="small")
        
        # Scenario 0: Clean Logs
        with btn_col0:
            is_active_0 = (current_source == "demo" and current_scenario_id == "clean_logs")
            btn_label_0 = "✓ CLEAN LOGS" if is_active_0 else "CLEAN LOGS"
            card_class_0 = "soc-scenario-card active" if is_active_0 else "soc-scenario-card"
            
            st.markdown(f"""
            <div class="{card_class_0}">
                <div class="soc-scenario-title-row">
                    <span class="soc-scenario-name">Clean Logs</span>
                    <span class="soc-scenario-badge soc-badge-low">LOW</span>
                </div>
                <div class="soc-scenario-desc">Normal baseline activity with no detected adversary attack.</div>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button(btn_label_0, key="btn_scen_clean", use_container_width=True):
                scenario_data = get_demo_scenario("clean_logs")
                st.session_state["data_source"] = "demo"
                st.session_state["selected_scenario"] = "clean_logs"
                st.session_state["dataset"] = scenario_data
                st.session_state["metrics"] = scenario_data["metrics"]
                st.rerun()

        # Scenario 1: USB Exfiltration
        with btn_col1:
            is_active_1 = (current_source == "demo" and current_scenario_id == "usb_exfiltration")
            btn_label_1 = "✓ USB EXFILTRATION" if is_active_1 else "USB EXFILTRATION"
            card_class_1 = "soc-scenario-card active" if is_active_1 else "soc-scenario-card"
            
            st.markdown(f"""
            <div class="{card_class_1}">
                <div class="soc-scenario-title-row">
                    <span class="soc-scenario-name">USB Exfiltration</span>
                    <span class="soc-scenario-badge soc-badge-high">HIGH</span>
                </div>
                <div class="soc-scenario-desc">Suspicious mass file staging and transfer to removable drive.</div>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button(btn_label_1, key="btn_scen_usb", use_container_width=True):
                scenario_data = get_demo_scenario("usb_exfiltration")
                st.session_state["data_source"] = "demo"
                st.session_state["selected_scenario"] = "usb_exfiltration"
                st.session_state["dataset"] = scenario_data
                st.session_state["metrics"] = scenario_data["metrics"]
                st.rerun()

        # Scenario 2: Lateral Movement
        with btn_col2:
            is_active_2 = (current_source == "demo" and current_scenario_id == "lateral_movement")
            btn_label_2 = "✓ LATERAL MOVEMENT" if is_active_2 else "LATERAL MOVEMENT"
            card_class_2 = "soc-scenario-card active" if is_active_2 else "soc-scenario-card"
            
            st.markdown(f"""
            <div class="{card_class_2}">
                <div class="soc-scenario-title-row">
                    <span class="soc-scenario-name">Lateral Movement</span>
                    <span class="soc-scenario-badge soc-badge-critical">CRITICAL</span>
                </div>
                <div class="soc-scenario-desc">Pass-the-Hash and pivot across workstations toward DC.</div>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button(btn_label_2, key="btn_scen_lateral", use_container_width=True):
                scenario_data = get_demo_scenario("lateral_movement")
                st.session_state["data_source"] = "demo"
                st.session_state["selected_scenario"] = "lateral_movement"
                st.session_state["dataset"] = scenario_data
                st.session_state["metrics"] = scenario_data["metrics"]
                st.rerun()

    # Right Column: Custom Log Upload
    with col_upload:
        st.markdown("<div style='font-size:0.78rem; font-weight:600; color:#cbd5e1; margin-bottom:0.5rem;'>UPLOAD CUSTOM LOGS</div>", unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Upload log file",
            type=["csv", "json", "log", "txt"],
            accept_multiple_files=False,
            help="Supported formats: CSV, JSON, TXT, LOG",
            key="custom_log_file_uploader",
            label_visibility="collapsed"
        )

        # Process upload if new file provided
        if uploaded_file is not None:
            # Check if this is a newly uploaded file or previously stored
            current_stored_file = st.session_state.get("uploaded_file_name")
            if current_stored_file != uploaded_file.name:
                result = load_dataset(uploaded_file)
                st.session_state["uploaded_file_name"] = uploaded_file.name
                st.session_state["custom_dataset_result"] = result
                
                if result["status"] == "success":
                    st.session_state["data_source"] = "custom"
                    st.session_state["dataset"] = result
                    st.session_state["metrics"] = result["metrics"]
                    st.rerun()

        # Display upload status feedback
        custom_result = st.session_state.get("custom_dataset_result")
        if current_source == "custom" and custom_result and custom_result.get("status") == "success":
            st.markdown(f"""
            <div class="soc-upload-status success">
                <div>
                    <span style="color: #34d399; font-weight: 600;">✓ Dataset loaded: </span>
                    <span style="color: #ffffff;">{custom_result['file_name']}</span>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #94a3b8;">
                    Type: {custom_result['file_type']} | Size: {custom_result['file_size']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        elif custom_result and custom_result.get("status") == "error":
            st.markdown(f"""
            <div class="soc-upload-status error">
                <div style="color: #f87171; font-weight: 500;">
                    ⚠️ {custom_result['error_message']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="soc-upload-status">
                <span style="color: #64748b;">○ No custom dataset active (using demo preset)</span>
                <span style="font-size: 0.7rem; color: #475569;">Supported: CSV, JSON, LOG, TXT</span>
            </div>
            """, unsafe_allow_html=True)
