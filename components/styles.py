"""
SOC Dark Theme & Custom Stylesheet
Provides clean, high-contrast, professional cybersecurity SOC styling.
"""

import streamlit as st

SOC_CSS = """
<style>
/* Import Cyber/Modern Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --soc-bg-dark: #070a12;
    --soc-bg-card: #0d1424;
    --soc-bg-card-hover: #121c33;
    --soc-border: #1e293b;
    --soc-border-accent: #2a3a55;
    --soc-cyan: #00e5ff;
    --soc-blue: #3b82f6;
    --soc-emerald: #10b981;
    --soc-amber: #f59e0b;
    --soc-crimson: #ef4444;
    --soc-text-primary: #f1f5f9;
    --soc-text-secondary: #94a3b8;
    --soc-text-muted: #64748b;
    --soc-font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --soc-font-mono: 'JetBrains Mono', monospace;
}

/* Global Container & Background Reset */
.stApp {
    background-color: var(--soc-bg-dark);
    font-family: var(--soc-font-sans);
    color: var(--soc-text-primary);
}

/* Reduce top padding */
.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2.5rem;
    max-width: 1440px;
}

/* Header Container */
.soc-header-container {
    background: linear-gradient(135deg, #0e172a 0%, #080d1a 100%);
    border: 1px solid var(--soc-border);
    border-left: 4px solid var(--soc-cyan);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.soc-header-left {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.soc-header-title {
    font-family: var(--soc-font-mono);
    font-size: 1.6rem;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: #ffffff;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.soc-header-badge {
    background: rgba(0, 229, 255, 0.12);
    border: 1px solid rgba(0, 229, 255, 0.4);
    color: var(--soc-cyan);
    font-size: 0.65rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    letter-spacing: 1px;
}

.soc-header-subtitle {
    font-size: 0.88rem;
    color: var(--soc-text-secondary);
    margin: 0;
    font-weight: 400;
}

.soc-status-badge {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.35);
    color: var(--soc-emerald);
    padding: 0.45rem 0.9rem;
    border-radius: 6px;
    font-family: var(--soc-font-mono);
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.8px;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.soc-pulse-dot {
    width: 8px;
    height: 8px;
    background-color: var(--soc-emerald);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--soc-emerald);
    display: inline-block;
    animation: pulse-animation 2s infinite ease-in-out;
}

@keyframes pulse-animation {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.2); opacity: 1; box-shadow: 0 0 12px var(--soc-emerald); }
    100% { transform: scale(0.95); opacity: 0.8; }
}

/* Section Wrapper */
.soc-section {
    background: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
}

.soc-section-title {
    font-family: var(--soc-font-mono);
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 1.2px;
    color: var(--soc-cyan);
    margin: 0 0 1rem 0;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* Metric Cards */
.soc-metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.25rem;
}

.soc-metric-card {
    background: linear-gradient(180deg, #0f182b 0%, #0a101f 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.1rem 1.25rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.15s ease, border-color 0.15s ease;
}

.soc-metric-card:hover {
    border-color: var(--soc-border-accent);
}

.soc-metric-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 2px;
    background: var(--soc-border);
}

.soc-metric-card.accent-cyan::before { background: var(--soc-cyan); }
.soc-metric-card.accent-blue::before { background: var(--soc-blue); }
.soc-metric-card.accent-amber::before { background: var(--soc-amber); }
.soc-metric-card.accent-crimson::before { background: var(--soc-crimson); }

.soc-metric-label {
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.9px;
    color: var(--soc-text-secondary);
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

.soc-metric-value {
    font-family: var(--soc-font-mono);
    font-size: 1.75rem;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.2;
    margin-bottom: 0.25rem;
}

.soc-metric-meta {
    font-size: 0.75rem;
    color: var(--soc-text-muted);
}

.soc-threat-pill-critical {
    display: inline-block;
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.5);
    color: #f87171;
    font-size: 1.25rem;
    font-weight: 700;
    padding: 0.1rem 0.6rem;
    border-radius: 4px;
    letter-spacing: 1px;
}

/* Data Source Control Cards */
.soc-datasource-card {
    background: #090e1c;
    border: 1px dashed var(--soc-border-accent);
    border-radius: 6px;
    padding: 1.25rem;
    text-align: center;
    min-height: 140px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    transition: all 0.2s ease;
}

.soc-datasource-card:hover {
    border-color: var(--soc-cyan);
    background: #0d1529;
}

.soc-datasource-icon {
    font-size: 1.5rem;
    color: var(--soc-cyan);
    margin-bottom: 0.5rem;
}

.soc-datasource-heading {
    font-family: var(--soc-font-mono);
    font-size: 0.88rem;
    font-weight: 600;
    color: #ffffff;
    margin-bottom: 0.35rem;
}

.soc-datasource-subtext {
    font-size: 0.78rem;
    color: var(--soc-text-secondary);
    max-width: 320px;
    margin: 0 auto;
}

/* Attack Graph Big Placeholder */
.soc-graph-container {
    background: radial-gradient(circle at center, #0e172a 0%, #080c14 100%);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.25rem;
    position: relative;
    min-height: 480px;
    display: flex;
    flex-direction: column;
}

.soc-graph-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--soc-border);
    padding-bottom: 0.75rem;
    margin-bottom: 1rem;
}

.soc-graph-canvas-placeholder {
    flex: 1;
    background: 
        linear-gradient(rgba(30, 41, 59, 0.3) 1px, transparent 1px),
        linear-gradient(90deg, rgba(30, 41, 59, 0.3) 1px, transparent 1px);
    background-size: 32px 32px;
    border: 1px dashed #1e293b;
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding: 3rem 1.5rem;
    text-align: center;
    min-height: 380px;
}

.soc-graph-placeholder-icon {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    background: rgba(0, 229, 255, 0.08);
    border: 1px solid rgba(0, 229, 255, 0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 1.25rem;
    color: var(--soc-cyan);
    font-size: 1.75rem;
}

.soc-graph-placeholder-title {
    font-family: var(--soc-font-mono);
    font-size: 1.1rem;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.8px;
    margin-bottom: 0.5rem;
}

.soc-graph-placeholder-msg {
    font-size: 0.85rem;
    color: var(--soc-text-secondary);
    max-width: 440px;
    line-height: 1.5;
    margin-bottom: 1rem;
}

.soc-graph-slot-tag {
    font-family: var(--soc-font-mono);
    font-size: 0.72rem;
    background: #0f172a;
    border: 1px solid var(--soc-border-accent);
    color: var(--soc-cyan);
    padding: 0.3rem 0.8rem;
    border-radius: 4px;
}

/* Status / Info Footer Container */
.soc-info-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 1rem;
}

.soc-info-card {
    background: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
}

.soc-info-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
    padding: 0.35rem 0;
    border-bottom: 1px solid rgba(30, 41, 59, 0.5);
}

.soc-info-row:last-child {
    border-bottom: none;
}

.soc-info-key {
    color: var(--soc-text-secondary);
    font-family: var(--soc-font-mono);
}

.soc-info-val {
    color: var(--soc-text-primary);
    font-weight: 500;
    font-family: var(--soc-font-mono);
}

/* Responsive adjustments */
@media (max-width: 1024px) {
    .soc-metric-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .soc-info-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 640px) {
    .soc-metric-grid {
        grid-template-columns: 1fr;
    }
    .soc-header-container {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.75rem;
    }
}
</style>
"""

def inject_soc_styles():
    """Injects custom SOC styling into Streamlit DOM."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)
