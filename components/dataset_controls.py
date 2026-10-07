"""
Data Source Section Component.
Visual structure and placeholder controls for Custom Log Upload and Demo Scenarios.
Ready for integration with file upload handlers and scenario loaders in subsequent tasks.
"""

import streamlit as st

def render_datasource_controls():
    """
    Renders the visual container for selecting data sources:
    - Custom Log Upload
    - Pre-packaged Demo Scenarios
    """
    st.markdown('<div class="soc-section-title">📂 DATA SOURCE SELECTION</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2, gap="medium")
    
    with col1:
        custom_upload_card = """
        <div class="soc-datasource-card">
            <div class="soc-datasource-icon">📤</div>
            <div class="soc-datasource-heading">CUSTOM LOG UPLOAD</div>
            <div class="soc-datasource-subtext">
                Ingest authentication, firewall, endpoint (EDR), and network telemetry logs (.csv, .json, .log).
            </div>
        </div>
        """
        st.markdown(custom_upload_card, unsafe_allow_html=True)
        # Placeholder interactive boundary for next phase
        st.file_uploader(
            "Upload Log Files (Integration Slot)",
            type=["csv", "json", "log"],
            accept_multiple_files=False,
            disabled=True,
            help="Custom log ingestion pipeline will be activated in the next phase.",
            key="placeholder_uploader"
        )
        
    with col2:
        demo_scenario_card = """
        <div class="soc-datasource-card">
            <div class="soc-datasource-icon">🎯</div>
            <div class="soc-datasource-heading">DEMO SCENARIOS</div>
            <div class="soc-datasource-subtext">
                Pre-configured multi-stage cyber attack chains for instant validation and judging demonstration.
            </div>
        </div>
        """
        st.markdown(demo_scenario_card, unsafe_allow_html=True)
        # Placeholder selector boundary for next phase
        st.selectbox(
            "Select Preloaded Scenario (Integration Slot)",
            options=[
                "Scenario 1: Ransomware & Data Exfiltration (APT29 Profile)",
                "Scenario 2: Lateral Movement & Credential Dumping (Mimikatz)",
                "Scenario 3: Multi-Stage DDoS & C2 Infrastructure"
            ],
            disabled=True,
            help="Demo scenario loader will be activated in the next phase.",
            key="placeholder_scenario_selector"
        )
