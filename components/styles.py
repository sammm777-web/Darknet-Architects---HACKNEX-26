"""
SOC Dark Theme & Professional Enterprise Cybersecurity Stylesheet.
Refined for an authentic, human-designed SOC operations interface.
Features clean typography, restrained accents, subtle borders, and balanced spacing.
"""

import streamlit as st

SOC_CSS = """
<style>
/* Modern Clean Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --soc-bg-base: #070b14;
    --soc-bg-surface: #0c1322;
    --soc-bg-card: #0f182b;
    --soc-bg-card-hover: #132038;
    --soc-bg-input: #0a0f1d;
    
    --soc-border: #1a263d;
    --soc-border-subtle: #151f33;
    --soc-border-active: #38bdf8;
    
    --soc-accent-primary: #38bdf8;
    --soc-accent-blue: #3b82f6;
    --soc-accent-emerald: #10b981;
    --soc-accent-amber: #f59e0b;
    --soc-accent-crimson: #ef4444;
    
    --soc-text-title: #ffffff;
    --soc-text-primary: #e2e8f0;
    --soc-text-secondary: #94a3b8;
    --soc-text-muted: #64748b;
    
    --soc-font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --soc-font-mono: 'JetBrains Mono', monospace;
}

/* Base Body & App Background */
.stApp {
    background-color: var(--soc-bg-base);
    font-family: var(--soc-font-sans);
    color: var(--soc-text-primary);
}

/* Page Layout Container */
.main .block-container {
    padding-top: 1.25rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1440px;
}

/* Custom Clean Scrollbar */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: #070b14;
}
::-webkit-scrollbar-thumb {
    background: #1a263d;
    border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
    background: #38bdf8;
}

/* ====================================================================
   HEADER COMPONENT
   ==================================================================== */
.soc-header-container {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-left: 3px solid var(--soc-accent-primary);
    border-radius: 8px;
    padding: 1.15rem 1.4rem;
    margin-bottom: 1.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
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
    letter-spacing: 0.5px;
    color: #ffffff;
    margin: 0;
}

.soc-header-badge {
    background: rgba(56, 189, 248, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.3);
    color: #38bdf8;
    font-family: var(--soc-font-mono);
    font-size: 0.65rem;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 4px;
}

.soc-header-subtitle {
    font-size: 0.85rem;
    color: var(--soc-text-secondary);
    margin: 0;
    font-weight: 400;
}

.soc-header-right {
    display: flex;
    align-items: center;
    gap: 0.85rem;
}

.soc-status-badge {
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #34d399;
    padding: 0.45rem 0.85rem;
    border-radius: 6px;
    font-family: var(--soc-font-mono);
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.soc-pulse-dot {
    width: 8px;
    height: 8px;
    background-color: #10b981;
    border-radius: 50%;
    display: inline-block;
    animation: pulse-dot 2.5s infinite ease-in-out;
}

@keyframes pulse-dot {
    0% { opacity: 0.7; transform: scale(0.9); }
    50% { opacity: 1; transform: scale(1.15); box-shadow: 0 0 6px rgba(16, 185, 129, 0.6); }
    100% { opacity: 0.7; transform: scale(0.9); }
}

/* ====================================================================
   DATASET ACTIVE STATUS STRIP
   ==================================================================== */
.soc-active-source-strip {
    background: #090e1c;
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.55rem 1rem;
    margin-bottom: 1.25rem;
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
    font-size: 0.7rem;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 4px;
}
.soc-source-tag.demo { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
.soc-source-tag.custom { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

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
    letter-spacing: 0.5px;
    color: #e2e8f0;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin: 0;
}

.soc-section-subtitle {
    font-size: 0.72rem;
    color: var(--soc-text-muted);
}

/* ====================================================================
   DATA SOURCE CONTROL SECTION
   ==================================================================== */
.soc-datasource-container {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.15rem;
    margin-bottom: 1.25rem;
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
    transition: border-color 0.15s ease, background 0.15s ease;
    cursor: pointer;
    text-align: left;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.soc-scenario-card:hover {
    border-color: #2b3b59;
    background: var(--soc-bg-card-hover);
}

.soc-scenario-card.active {
    border-color: var(--soc-accent-primary);
    background: #0f1c33;
    box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.3);
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
    color: #ffffff;
}

.soc-scenario-badge {
    font-family: var(--soc-font-mono);
    font-size: 0.62rem;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
}
.soc-badge-low { background: rgba(16, 185, 129, 0.12); color: #34d399; }
.soc-badge-high { background: rgba(245, 158, 11, 0.12); color: #fbbf24; }
.soc-badge-critical { background: rgba(239, 68, 68, 0.12); color: #f87171; }

.soc-scenario-desc {
    font-size: 0.74rem;
    color: var(--soc-text-secondary);
    line-height: 1.35;
}

/* Upload Status Box */
.soc-upload-status {
    background: #090e1c;
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
    border-color: rgba(16, 185, 129, 0.35);
    background: rgba(16, 185, 129, 0.05);
}

.soc-upload-status.error {
    border-color: rgba(239, 68, 68, 0.35);
    background: rgba(239, 68, 68, 0.05);
}

/* ====================================================================
   METRIC CARDS
   ==================================================================== */
.soc-metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.9rem;
    margin-bottom: 1.25rem;
}

.soc-metric-card {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1rem 1.15rem;
    position: relative;
    transition: border-color 0.15s ease;
}

.soc-metric-card:hover {
    border-color: #2a3a55;
}

.soc-metric-card.accent-cyan { border-top: 2px solid var(--soc-accent-primary); }
.soc-metric-card.accent-blue { border-top: 2px solid var(--soc-accent-blue); }
.soc-metric-card.accent-amber { border-top: 2px solid var(--soc-accent-amber); }
.soc-metric-card.accent-crimson { border-top: 2px solid var(--soc-accent-crimson); }

.soc-metric-label {
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--soc-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    margin-bottom: 0.4rem;
}

.soc-metric-value {
    font-family: var(--soc-font-mono);
    font-size: 1.65rem;
    font-weight: 700;
    color: #ffffff;
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
}
.soc-threat-pill.critical { background: rgba(239, 68, 68, 0.12); color: #f87171; }
.soc-threat-pill.high { background: rgba(245, 158, 11, 0.12); color: #fbbf24; }
.soc-threat-pill.low { background: rgba(16, 185, 129, 0.12); color: #34d399; }
.soc-threat-pill.analyzing { background: rgba(56, 189, 248, 0.12); color: #38bdf8; }

/* ====================================================================
   ATTACK GRAPH WORKSPACE CONTAINER & ENTITY INSPECTOR
   ==================================================================== */
.soc-graph-container {
    background: var(--soc-bg-surface);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.15rem;
    margin-bottom: 1.25rem;
    min-height: 460px;
    display: flex;
    flex-direction: column;
}

.soc-graph-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #090e1c;
    border: 1px solid var(--soc-border-subtle);
    border-radius: 6px;
    padding: 0.45rem 0.8rem;
    margin-bottom: 0.85rem;
}

.soc-toolbar-info {
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    color: var(--soc-text-secondary);
}

.soc-graph-controls-strip {
    background: #090e1c;
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.6rem 0.85rem;
    margin-bottom: 0.75rem;
}

/* Entity Inspector Panel */
.soc-entity-panel {
    background: var(--soc-bg-surface);
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
    color: #ffffff;
    text-transform: uppercase;
}

.soc-entity-empty {
    padding: 2.2rem 1.5rem;
    text-align: center;
    color: var(--soc-text-muted);
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    background: #080c16;
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
    background: #090e1c;
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
    color: #ffffff;
    word-break: break-all;
}

.soc-legend-panel {
    background: var(--soc-bg-surface);
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
    background: #090e1c;
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
    background: var(--soc-bg-surface);
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
    border-bottom: 1px solid rgba(21, 31, 51, 0.6);
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

/* Streamlit Native Elements Clean Integration */
div.stButton > button {
    background-color: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    color: #e2e8f0;
    font-family: var(--soc-font-mono);
    font-size: 0.78rem;
    font-weight: 500;
    padding: 0.5rem 0.9rem;
    border-radius: 6px;
    transition: all 0.15s ease;
    width: 100%;
}

div.stButton > button:hover {
    border-color: var(--soc-accent-primary);
    background-color: var(--soc-bg-card-hover);
    color: #ffffff;
}

div.stButton > button:active, div.stButton > button:focus {
    border-color: var(--soc-accent-primary);
    box-shadow: 0 0 0 1px var(--soc-accent-primary);
}

div[data-testid="stFileUploader"] section {
    background: #090e1c !important;
    border: 1px dashed var(--soc-border) !important;
    border-radius: 6px !important;
    padding: 0.65rem !important;
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
