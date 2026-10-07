# 🛡️ Cyber Threat Command Center (SOC)
> **Darknet Architects — HACKNEX-26**  
> An enterprise-grade Security Operations Center (SOC) dashboard and interactive attack-path visualization platform built for threat detection, log telemetry analysis, and incident response.

---

## 📌 Overview

The **Cyber Threat Command Center** is a cybersecurity monitoring and threat intelligence dashboard designed with an enterprise SOC aesthetic. Built on Streamlit, the platform combines real-time telemetry metrics, automated multi-format log ingestion, scenario-based adversary simulation, and a structured **Hybrid Hierarchical Attack-Path Graph** to help security analysts understand and triage complex multi-stage intrusions at a glance.

---

## ✨ Key Features

### 1. 🎛️ Enterprise SOC Command Dashboard
- **Obsidian & Electric Teal Palette**: Designed with a high-contrast dark theme (`#05080E` / `#00E5C7`), carbon micro-textures, and luminous 1px panel borders.
- **Live DEFCON Status**: Dynamic threat level banner with pulsing visual indicators and operational status telemetry.
- **Dynamic Metric Cards**: Real-time display of total log volume, benign vs. anomalous events, active attack chains, and current severity.

### 2. 📥 Multi-Format Log Ingestion Engine
- Supports automated parsing and validation for multiple security log formats:
  - **CSV** (Comma-separated security event tables)
  - **JSON** (Structured authentication, audit, and firewall logs)
  - **LOG / TXT** (Raw syslog and endpoint telemetry)
- Built-in validation safeguards against corrupt, empty, or unsupported files with user-friendly error boundaries.

### 3. 🎯 Pre-Packaged MITRE ATT&CK Scenarios
- **Scenario 0: Clean Logs (`LOW` Risk)**  
  Enterprise baseline activity with normal Kerberos ticket requests (`AUTH_TGS`), SMB shares (`SMB_CONNECT`), and authorized file access.
- **Scenario 1: USB Exfiltration (`HIGH` Risk // MITRE T1052.001)**  
  Detects unauthorized physical removable storage mounts on workstations, rapid staging of sensitive `.xlsx` archives, and offline exfiltration.
- **Scenario 2: Lateral Movement (`CRITICAL` Risk // MITRE T1021.002, T1003.001)**  
  Simulates a multi-stage intrusion involving DMZ C2 ingress, LSASS memory credential dumping, Pass-the-Hash authentication, and pivot to the Primary Domain Controller crown jewel.

### 4. 🌐 Hybrid Hierarchical Attack-Path Graph
- **Structured Multi-Level Tree Flow**: Replaces chaotic physics networks with a deterministic top-to-bottom hierarchy:
  ```
                      Domain Controller
                      /               \
                     /                 \
            File Server              WS-ALPHA
                 |                       |
                 |                       |
     Quarterly_Budget.xlsx             alice
  ```
- **Enterprise Node Cards**: Rounded card components with visual entity badges (`⚔️ Attacker / Target`, `🖧 Server`, `💻 Device`, `👤 User`, `📄 File`, `🔌 USB Media`), entity labels, and status taxonomy.
- **Curved Directional Edges & Protocol Labels**: Smooth cubic Bézier connection splines displaying protocol badges (`SMB_CONNECT`, `AUTH_TGS`, `LOGON`, `FILE_READ`).
- **Attack-Path Emphasis**: One-click attack path highlighting that illuminates the adversary path in bold crimson (`#E63946`) while dimming benign infrastructure to maintain complete operational context.
- **Left-Aligned Legend**: Dedicated legend panel categorizing Node Types and Relationship Types alongside active MITRE attack chains.
- **Top Control Toolbar**: Entity Type filtering, label toggles, node inspection dropdown, and instant state reset.

### 5. 🔍 Deep Entity Inspection Panel
- Detailed telemetry breakdown for any selected node (Associated IP, Host/Device, Role, First Seen, Last Activity, Risk Rating, and context-specific attributes).

---

## 🏗️ Project Architecture

```
Darknet-Architects---HACKNEX-26/
├── app.py                      # Main SOC dashboard orchestrator & Streamlit entrypoint
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── .gitignore                  # Git exclusion rules
├── .streamlit/
│   └── config.toml             # Streamlit theme tokens and server configuration
├── components/                 # Modular SOC UI components
│   ├── header.py               # Header with DEFCON status badge
│   ├── dataset_controls.py     # Log uploader and scenario selection cards
│   ├── metric_cards.py         # Real-time telemetry metric cards
│   ├── attack_graph.py         # Hierarchical SVG attack graph & inspection panel
│   ├── status_info.py          # Session and dataset status telemetry
│   └── styles.py               # Enterprise dark stylesheet (CSS injection)
├── data/                       # Data layer and threat models
│   ├── data_loader.py          # Log ingestion and format parser (CSV/JSON/LOG/TXT)
│   ├── demo_scenarios.py       # Pre-configured demo scenarios & metadata
│   └── graph_demo_data.py      # Standardized node & edge topology datasets
└── tests/
    ├── test_graph_flow.py      # Unit test suite for graph generation & hierarchy
    └── test_data_flow.py       # Unit test suite for log parser & error handling
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- **Python 3.10+**
- **pip** package manager

### 1. Clone the Repository
```bash
git clone https://github.com/sammm777-web/Darknet-Architects---HACKNEX-26.git
cd Darknet-Architects---HACKNEX-26
```

### 2. Create and Activate Virtual Environment (Recommended)
```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit Application
```bash
streamlit run app.py
```
Open your browser and navigate to `http://localhost:8501`.

---

## 🧪 Testing & Verification

The repository includes automated unit test suites covering the data pipeline and attack graph rendering engine:

```bash
# Run Attack Graph & Hierarchical Layout Unit Tests
python test_graph_flow.py

# Run Data Ingestion & Parser Unit Tests
python test_data_flow.py
```

### Test Coverage Highlights:
- ✅ Scenario graph structures (Clean Logs, USB Exfiltration, Lateral Movement)
- ✅ Hierarchical coordinate calculations (Level 0 $\to$ Level 1 $\to$ Level 2 tree branching)
- ✅ Protocol label extraction (`SMB_CONNECT`, `AUTH_TGS`, `LOGON`)
- ✅ Graph control state variants (Filtering, Attack Highlighting, Label Toggles, Empty Inputs)
- ✅ Multi-format file parsing (CSV, JSON, LOG, TXT) and corrupted file boundary handling

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend Framework** | [Streamlit](https://streamlit.io/) | Dashboard orchestration and reactive session state |
| **Graph Visualization** | SVG / HTML5 + [NetworkX](https://networkx.org/) | Structured hierarchical attack-path rendering |
| **Data Processing** | [Pandas](https://pandas.pydata.org/) | High-performance log parsing and schema normalization |
| **Styling & Theme** | Vanilla CSS3 (Glassmorphism & Obsidian) | Enterprise SOC Command Center visual identity |
| **Compatibility Layer**| [PyVis](https://pyvis.readthedocs.io/) | Force-directed graph compatibility |

---

## 👥 Team — Darknet Architects (HACKNEX-26)

- **Team**: Darknet Architects
- **Hackathon**: HACKNEX-26
- **Project**: Cyber Threat Command Center
- **Repository**: [sammm777-web/Darknet-Architects---HACKNEX-26](https://github.com/sammm777-web/Darknet-Architects---HACKNEX-26)
