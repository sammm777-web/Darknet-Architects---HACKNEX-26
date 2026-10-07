# Darknet-Architects - ChainSight (HACKNEX '26)

**Problem Statement:** HNX26PSI03 - AI-Powered Cyber Threat Intelligence & Forensic Incident Correlation.

ChainSight is a forensic incident correlation and threat intelligence platform that reconstructs multi-stage cyber campaigns from raw audit logs, computes deterministic explainable risk scores, isolates affected entities, and produces verified intelligence reports with evidence citation.

---

## Architecture Overview

- **`backend/graph_builder.py`**: MultiDiGraph entity relation mapper with betweenness-centrality pivot detection, shortest attack path calculation, node coloring (red/blue/green/gray), and isolated host containment.
- **`backend/ai_explainer.py`**: Deterministic scoring engine (`compute_risk`), strict evidence citation firewall (`validate_citations`), OpenAI reasoning orchestrator (`gpt-4o-mini`) with 1-retry fallback to deterministic templates, and cache management.
- **`data/`**: Standardized mock security event logs (`mock_logs.json`), correlated multi-stage attack chains (`mock_chains.json`), pre-computed graph topologies (`mock_graph.json`), and verified forensic reports (`mock_report.json`).
- **`cache/`**: Pre-generated, verified threat intelligence reports (`C-1.json`, `C-2.json`) for instant offline loading and dashboard execution.
- **`tests/`**: Test suite covering contract hygiene, graph algorithms, evidence verification, and AI fallback behavior.
- **`scripts/run_drills.py`**: Definition-of-Done drills verifying citation verification, offline fallback, scoring determinism, and IP isolation.
- **`HANDOFF.md`**: Integration handoff specification for Member 3 (Command Center / Streamlit UI) and Member 4 (Timeline UI / Playbooks).

---

## Running Drills & Tests

```bash
# Run contract schema & cross-reference checks
python tests/check_mocks.py

# Run NetworkX graph builder tests
python tests/test_graph.py

# Run core evidence firewall & determinism tests
python tests/test_core.py

# Run AI fallback & cache tests
python tests/test_ai.py

# Execute Definition-of-Done drills
python scripts/run_drills.py
```
