"""
Enterprise SOC Dark Theme & High-End Cybersecurity Stylesheet.
Designed for a premium CrowdStrike / Splunk caliber command center interface.

Palette Tokens:
- Base: Deep Obsidian-Black (#05080E) with subtle carbon micro-texture
- Surfaces: Obsidian Slate (#090E17, #0D1422, #111A2C)
- Primary Accent: Electric Teal (#00E5C7)
- Alert & DEFCON: Crimson-Red (#FF3B5C)
- Secondary Text: Soft Slate-Gray (#8A94A6)
- Primary Body Text: Off-White (#E8ECF1)
- Luminous Borders: 1px subtle glow borders (rgba(0, 229, 199, 0.16) / #162338)
"""

import streamlit as st

SOC_CSS = """
<style>
/* Modern Precision Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --soc-bg-base: #05080E;
    --soc-bg-surface: #090E17;
    --soc-bg-card: #0D1422;
    --soc-bg-card-hover: #111A2C;
    --soc-bg-input: #070C14;
    
    --soc-border: #162338;
    --soc-border-subtle: #101928;
    --soc-border-luminous: rgba(0, 229, 199, 0.22);
    --soc-border-alert: rgba(255, 59, 92, 0.35);
    
    --soc-accent-teal: #00E5C7;
    --soc-accent-teal-dim: rgba(0, 229, 199, 0.12);
    --soc-accent-crimson: #FF3B5C;
    --soc-accent-crimson-dim: rgba(255, 59, 92, 0.14);
    --soc-accent-amber: #F59E0B;
    --soc-accent-blue: #38BDF8;
    
    --soc-text-title: #FFFFFF;
    --soc-text-primary: #E8ECF1;
    --soc-text-secondary: #8A94A6;
    --soc-text-muted: #5A6478;
    
    --soc-font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --soc-font-mono: 'JetBrains Mono', monospace;
}

/* Base Body & Carbon Texture Background */
.stApp {
    background-color: var(--soc-bg-base);
    background-image: 
        radial-gradient(circle at 50% 0%, #0a1324 0%, transparent 60%),
        radial-gradient(rgba(0, 229, 199, 0.02) 1px, transparent 0);
    background-size: 100% 100%, 28px 28px;
    font-family: var(--soc-font-sans);
    color: var(--soc-text-primary);
}

/* Main Container Spacing */
.main .block-container {
    padding-top: 1.15rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1440px;
}

/* Sleek Obsidian Scrollbar */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: #05080E;
}
::-webkit-scrollbar-thumb {
    background: #162338;
    border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
    background: #00E5C7;
}

/* ====================================================================
   HEADER COMPONENT & DEFCON STATUS
   ==================================================================== */
.soc-header-container {
    background: linear-gradient(180deg, #0B1220 0%, #080D18 100%);
    border: 1px solid var(--soc-border);
    border-left: 3px solid var(--soc-accent-teal);
    border-radius: 8px;
    padding: 1.15rem 1.4rem;
    margin-bottom: 1.2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5), 0 0 1px rgba(0, 229, 199, 0.15);
}

.soc-header-left {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.soc-header-title-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.soc-header-title {
    font-family: var(--soc-font-mono);
    font-size: 1.4rem;
    font-weight: 700;
    letter-spacing: 0.75px;
    color: #FFFFFF;
    margin: 0;
}

.soc-header-badge {
    background: var(--soc-accent-teal-dim);
    border: 1px solid rgba(0, 229, 199, 0.35);
    color: var(--soc-accent-teal);
    font-family: var(--soc-font-mono);
    font-size: 0.65rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 4px;
    letter-spacing: 0.5px;
}

.soc-header-subtitle {
    font-size: 0.82rem;
    color: var(--soc-text-secondary);
    margin: 0;
    font-weight: 400;
}

.soc-header-right {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

/* DEFCON / System Alert Status with Subtle Crimson Pulse */
.soc-defcon-badge {
    background: rgba(255, 59, 92, 0.08);
    border: 1px solid rgba(255, 59, 92, 0.4);
    color: #FF3B5C;
    padding: 0.45rem 0.85rem;
    border-radius: 6px;
    font-family: var(--soc-font-mono);
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    box-shadow: 0 0 14px rgba(255, 59, 92, 0.18);
}

.soc-defcon-badge.online {
    background: rgba(0, 229, 199, 0.08);
    border: 1px solid rgba(0, 229, 199, 0.35);
    color: #00E5C7;
    box-shadow: 0 0 14px rgba(0, 229, 199, 0.15);
}

.soc-pulse-dot-red {
    width: 8px;
    height: 8px;
    background-color: #FF3B5C;
    border-radius: 50%;
    display: inline-block;
    box-shadow: 0 0 8px #FF3B5C;
    animation: pulse-red 2s infinite ease-in-out;
}

.soc-pulse-dot-teal {
    width: 8px;
    height: 8px;
    background-color: #00E5C7;
    border-radius: 50%;
    display: inline-block;
    box-shadow: 0 0 8px #00E5C7;
    animation: pulse-teal 2.5s infinite ease-in-out;
}

@keyframes pulse-red {
    0% { opacity: 0.6; transform: scale(0.85); box-shadow: 0 0 4px rgba(255, 59, 92, 0.4); }
    50% { opacity: 1; transform: scale(1.18); box-shadow: 0 0 12px rgba(255, 59, 92, 0.8); }
    100% { opacity: 0.6; transform: scale(0.85); box-shadow: 0 0 4px rgba(255, 59, 92, 0.4); }
}

@keyframes pulse-teal {
    0% { opacity: 0.6; transform: scale(0.9); box-shadow: 0 0 4px rgba(0, 229, 199, 0.4); }
    50% { opacity: 1; transform: scale(1.15); box-shadow: 0 0 10px rgba(0, 229, 199, 0.7); }
    100% { opacity: 0.6; transform: scale(0.9); box-shadow: 0 0 4px rgba(0, 229, 199, 0.4); }
}

/* ====================================================================
   DATASET ACTIVE STATUS STRIP
   ==================================================================== */
.soc-active-source-strip {
    background: #080D16;
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.55rem 1rem;
    margin-bottom: 1.2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
}

.soc-source-indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
}

.soc-source-tag {
    font-family: var(--soc-font-mono);
    font-size: 0.68rem;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 4px;
}
.soc-source-tag.demo { background: rgba(0, 229, 199, 0.12); color: #00E5C7; border: 1px solid rgba(0, 229, 199, 0.3); }
.soc-source-tag.custom { background: rgba(56, 189, 248, 0.12); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.3); }

/* ====================================================================
   SECTION HEADERS
   ==================================================================== */
.soc-section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 0 0 0.8rem 0;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid var(--soc-border-subtle);
}

.soc-section-title {
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.6px;
    color: #FFFFFF;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin: 0;
}

.soc-section-subtitle {
    font-size: 0.72rem;
    color: var(--soc-text-secondary);
}

/* ====================================================================
   DATA SOURCE CONTROL SECTION & INGESTION PORT
   ==================================================================== */
.soc-datasource-container {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.15rem;
    margin-bottom: 1.2rem;
}

.soc-scenario-btn-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
    margin-bottom: 0.75rem;
}

.soc-scenario-card {
    background: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.85rem;
    transition: all 0.2s ease;
    cursor: pointer;
    text-align: left;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.soc-scenario-card:hover {
    border-color: #243550;
    background: var(--soc-bg-card-hover);
}

.soc-scenario-card.active {
    border: 1px solid var(--soc-accent-teal);
    background: linear-gradient(145deg, #0D1E2B 0%, #0A1522 100%);
    box-shadow: 0 0 16px rgba(0, 229, 199, 0.12);
}

.soc-scenario-title-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.35rem;
}

.soc-scenario-name {
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    color: #FFFFFF;
}

.soc-scenario-badge {
    font-family: var(--soc-font-mono);
    font-size: 0.62rem;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
}
.soc-badge-low { background: rgba(0, 229, 199, 0.12); color: #00E5C7; border: 1px solid rgba(0, 229, 199, 0.25); }
.soc-badge-high { background: rgba(245, 158, 11, 0.12); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.25); }
.soc-badge-critical { background: var(--soc-accent-crimson-dim); color: #FF3B5C; border: 1px solid rgba(255, 59, 92, 0.3); }

.soc-scenario-desc {
    font-size: 0.74rem;
    color: var(--soc-text-secondary);
    line-height: 1.35;
}

/* Ingestion Port Glow */
div[data-testid="stFileUploader"] section {
    background: linear-gradient(145deg, #070D18 0%, #050912 100%) !important;
    border: 1px dashed rgba(0, 229, 199, 0.28) !important;
    border-radius: 6px !important;
    padding: 0.75rem !important;
    box-shadow: inset 0 0 12px rgba(0, 229, 199, 0.03);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

div[data-testid="stFileUploader"] section:hover {
    border-color: var(--soc-accent-teal) !important;
    box-shadow: 0 0 16px rgba(0, 229, 199, 0.12);
}

.soc-upload-status {
    background: #080D16;
    border: 1px solid var(--soc-border-subtle);
    border-radius: 6px;
    padding: 0.65rem 0.85rem;
    margin-top: 0.5rem;
    font-size: 0.78rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.soc-upload-status.success {
    border-color: rgba(0, 229, 199, 0.35);
    background: rgba(0, 229, 199, 0.06);
}

.soc-upload-status.error {
    border-color: rgba(255, 59, 92, 0.35);
    background: rgba(255, 59, 92, 0.06);
}

/* ====================================================================
   METRIC CARDS (Luminous 1px Borders)
   ==================================================================== */
.soc-metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.9rem;
    margin-bottom: 1.2rem;
}

.soc-metric-card {
    background: linear-gradient(180deg, #0C1322 0%, #090E18 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1rem 1.15rem;
    position: relative;
    transition: all 0.2s ease;
}

.soc-metric-card:hover {
    border-color: rgba(0, 229, 199, 0.3);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4), 0 0 12px rgba(0, 229, 199, 0.08);
}

.soc-metric-card.accent-teal { border-top: 2px solid var(--soc-accent-teal); }
.soc-metric-card.accent-blue { border-top: 2px solid var(--soc-accent-blue); }
.soc-metric-card.accent-amber { border-top: 2px solid var(--soc-accent-amber); }
.soc-metric-card.accent-crimson { border-top: 2px solid var(--soc-accent-crimson); }

.soc-metric-label {
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--soc-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 0.4rem;
}

.soc-metric-value {
    font-family: var(--soc-font-mono);
    font-size: 1.65rem;
    font-weight: 700;
    color: #FFFFFF;
    line-height: 1.2;
    margin-bottom: 0.3rem;
}

.soc-metric-subtext {
    font-size: 0.72rem;
    color: var(--soc-text-muted);
}

.soc-threat-pill {
    display: inline-block;
    font-family: var(--soc-font-mono);
    font-size: 1.1rem;
    font-weight: 700;
    padding: 0.1rem 0.5rem;
    border-radius: 4px;
    letter-spacing: 0.5px;
}
.soc-threat-pill.critical { background: var(--soc-accent-crimson-dim); color: #FF3B5C; border: 1px solid rgba(255, 59, 92, 0.3); box-shadow: 0 0 8px rgba(255, 59, 92, 0.2); }
.soc-threat-pill.high { background: rgba(245, 158, 11, 0.12); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.25); }
.soc-threat-pill.low { background: var(--soc-accent-teal-dim); color: #00E5C7; border: 1px solid rgba(0, 229, 199, 0.25); }
.soc-threat-pill.analyzing { background: rgba(56, 189, 248, 0.12); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.25); }

/* ====================================================================
   ATTACK GRAPH WORKSPACE & CONTROLS STRIP
   ==================================================================== */
.soc-graph-container {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.15rem;
    margin-bottom: 1.2rem;
    min-height: 460px;
    display: flex;
    flex-direction: column;
}

.soc-graph-controls-strip {
    background: #080D16;
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.6rem 0.85rem;
    margin-bottom: 0.75rem;
}

/* Entity Inspector Panel */
.soc-entity-panel {
    background: linear-gradient(180deg, #0C1322 0%, #090E18 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.1rem;
    height: 100%;
    display: flex;
    flex-direction: column;
}

.soc-entity-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.85rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--soc-border-subtle);
}

.soc-entity-title {
    font-family: var(--soc-font-mono);
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: #FFFFFF;
    text-transform: uppercase;
}

.soc-entity-empty {
    padding: 2.2rem 1.5rem;
    text-align: center;
    color: var(--soc-text-muted);
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    background: #070B14;
    border: 1px dashed var(--soc-border);
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.soc-entity-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.65rem;
    margin-top: 0.5rem;
}

.soc-entity-cell {
    background: #070B14;
    border: 1px solid var(--soc-border-subtle);
    border-radius: 6px;
    padding: 0.55rem 0.75rem;
}

.soc-entity-key {
    font-family: var(--soc-font-mono);
    font-size: 0.68rem;
    color: var(--soc-text-secondary);
    text-transform: uppercase;
    margin-bottom: 0.2rem;
}

.soc-entity-val {
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    color: #FFFFFF;
    word-break: break-all;
}

.soc-legend-panel {
    background: linear-gradient(180deg, #0C1322 0%, #090E18 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.1rem;
    height: 100%;
}

.soc-legend-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.soc-legend-item-box {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    color: var(--soc-text-primary);
    background: #070B14;
    border: 1px solid var(--soc-border-subtle);
    border-radius: 4px;
    padding: 0.4rem 0.6rem;
}

.soc-legend-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
}

.soc-legend-line {
    width: 14px;
    height: 3px;
    display: inline-block;
    border-radius: 1px;
}

/* ====================================================================
   STATUS & TELEMETRY SECTION
   ==================================================================== */
.soc-info-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 0.9rem;
}

.soc-info-card {
    background: linear-gradient(180deg, #0C1322 0%, #090E18 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1rem 1.15rem;
}

.soc-info-header {
    font-family: var(--soc-font-mono);
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--soc-text-primary);
    margin-bottom: 0.65rem;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid var(--soc-border-subtle);
    display: flex;
    justify-content: space-between;
}

.soc-info-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.78rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid rgba(16, 25, 40, 0.8);
}

.soc-info-row:last-child {
    border-bottom: none;
}

.soc-info-key {
    color: var(--soc-text-secondary);
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
}

.soc-info-val {
    color: var(--soc-text-primary);
    font-weight: 500;
    font-family: var(--soc-font-mono);
    font-size: 0.73rem;
}

/* ====================================================================
   STREAMLIT WIDGETS & BUTTONS (Electric Teal Glow)
   ==================================================================== */
div.stButton > button {
    background: linear-gradient(145deg, #0E1626 0%, #090F1B 100%);
    border: 1px solid #1A283F;
    color: #E8ECF1;
    font-family: var(--soc-font-mono);
    font-size: 0.78rem;
    font-weight: 500;
    padding: 0.5rem 0.9rem;
    border-radius: 6px;
    transition: all 0.2s ease;
    width: 100%;
}

div.stButton > button:hover {
    border-color: var(--soc-accent-teal);
    background: linear-gradient(145deg, #132238 0%, #0E1A2C 100%);
    color: #FFFFFF;
    box-shadow: 0 0 14px rgba(0, 229, 199, 0.18);
}

div.stButton > button:active, div.stButton > button:focus {
    border-color: var(--soc-accent-teal);
    box-shadow: 0 0 0 1px var(--soc-accent-teal), 0 0 16px rgba(0, 229, 199, 0.25);
}

/* Inputs & Dropdowns */
div[data-baseweb="select"] {
    background-color: #070B14 !important;
}

div[data-baseweb="select"] > div {
    background-color: #070B14 !important;
    border-color: #162338 !important;
    color: #E8ECF1 !important;
    font-family: var(--soc-font-mono) !important;
    font-size: 0.78rem !important;
}

/* Checkboxes */
span[data-baseweb="checkbox"] span {
    background-color: #070B14 !important;
    border-color: #162338 !important;
}

/* Responsive constraints */
@media (max-width: 1024px) {
    .soc-metric-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .soc-info-grid {
        grid-template-columns: 1fr;
    }
    .soc-scenario-btn-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 640px) {
    .soc-metric-grid {
        grid-template-columns: 1fr;
    }
}
</style>
"""

def inject_soc_styles():
    """Injects custom SOC styling into Streamlit DOM."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)
