# ChainSight Team Integration Handoff

## Member 3 (Command Center / pyvis)
**Signature:** `build_graph(chain: dict, logs: list[dict], blocked: set = frozenset(), context_logs: list[dict] = None) -> dict`
**Returns:** `{'nodes': [...], 'edges': [...]}` (JSON-serializable)
- `context_logs`: pass 10 to 15 normal rows from same window for green neighbor nodes (capped <= 8)
- Node keys: `id`, `label`, `type` ('user'|'ip'|'host'|'resource'), `color` ('red'|'blue'|'green'|'gray'), `status` ('active'|'isolated'), `is_pivot` (bool), `size` (float: `20 + 60 * centrality`)
- Edge keys: `source`, `target`, `action`, `timestamp`, `log_id`, `on_attack_path` (bool)
**Example:**
```python
from backend.graph_builder import build_graph
graph = build_graph(chain, incident_logs, blocked=st.session_state.get('blocked_ips', set()), context_logs=bg_logs)
for n in graph['nodes']:
    net.add_node(n['id'], label=n['label'], color=COLORS[n['color']], shape='star' if n['is_pivot'] else 'dot')
for e in graph['edges']:
    net.add_edge(e['source'], e['target'], label=e['action'], width=4 if e['on_attack_path'] else 1)
```

## Member 4 (Timeline / Proof Inspector / Playbook)
**Signature:** `generate_threat_intelligence(incident: dict) -> {'graph': dict, 'report': dict}`
- Note: only source `'ai'` reports are cached; source `'template'` reports are not written to cache
**Report Keys:** `summary` (str), `risk_score` (1-100), `risk_rationale` (str), `stages` (list), `recommendations` (list), `citations_verified` (bool), `source` ('cache'|'ai'|'template')
- `stages[*]`: `stage_no` (1..n), `log_ids` (list[str]), `timestamps` (list[str]), `explanation` (str)
- `recommendations[*]`: `action`, `target`, `why`
- Allowed actions: `{'block_ip', 'revoke_user_token', 'isolate_host', 'reset_credentials'}`
**Example:**
```python
from backend.ai_explainer import generate_threat_intelligence
incident = {'chain': chain, 'logs': incident_logs, 'blocked': blocked_ips, 'context_logs': bg_logs}
report = generate_threat_intelligence(incident)['report']  # citations_verified is True
for rec in report['recommendations']:
    if rec['action'] == 'block_ip':
        st.session_state['blocked_ips'].add(rec['target'])
```
