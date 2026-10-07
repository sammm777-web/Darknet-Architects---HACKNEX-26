"""
backend/graph_builder.py

Builds an entity relationship graph from security logs and attack chain data
using NetworkX, computing attack path, pivot node, and entity styling.
"""

from typing import Any, Dict, List, Optional, Set, Union
import networkx as nx


def build_graph(
    chain: Dict[str, Any],
    logs: List[Dict[str, Any]],
    blocked: Union[Set[str], frozenset] = frozenset(),
    context_logs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Constructs a GRAPH contract dict from an attack chain and supporting logs.

    Args:
        chain: CHAIN dict containing chain_id, entities, stages, etc.
        logs: List of LOG ROW dicts for the chain / incident.
        blocked: Set or collection of IP strings to mark as isolated.
        context_logs: Optional list of normal background activity log rows.

    Returns:
        Dict adhering to the GRAPH contract:
        {
            "nodes": [
                {
                    "id": str,
                    "label": str,
                    "type": str,
                    "color": str,
                    "status": str,
                    "is_pivot": bool,
                    "size": float,
                }
            ],
            "edges": [
                {
                    "source": str,
                    "target": str,
                    "action": str,
                    "timestamp": str,
                    "log_id": str,
                    "on_attack_path": bool,
                }
            ],
        }
    """
    blocked_set = set(blocked) if blocked else set()
    chain = chain or {}
    logs = logs or []

    # Combine logs with context_logs (normal background activity)
    all_logs = list(logs)
    if context_logs:
        seen_lids = {str(r.get("log_id")) for r in all_logs if r.get("log_id")}
        for r in context_logs:
            lid = str(r.get("log_id")) if r.get("log_id") else None
            if lid is None or lid not in seen_lids:
                all_logs.append(r)
                if lid:
                    seen_lids.add(lid)

    # 1. Initialize MultiDiGraph
    G = nx.MultiDiGraph()
    node_types: Dict[str, str] = {}

    for r in all_logs:
        user = str(r.get("user") or "unknown")
        src_ip = str(r.get("src_ip") or "unknown")
        host = str(r.get("host") or "unknown")
        resource = str(r.get("resource") or "unknown")

        for node_id, ntype in [
            (user, "user"),
            (src_ip, "ip"),
            (host, "host"),
            (resource, "resource"),
        ]:
            if node_id not in G:
                G.add_node(node_id, type=ntype)
                node_types[node_id] = ntype

        ts = str(r.get("timestamp", ""))
        lid = str(r.get("log_id", ""))
        action = str(r.get("action", ""))

        # user -> resource (action)
        G.add_edge(user, resource, action=action, timestamp=ts, log_id=lid)
        # user -> src_ip ('from')
        G.add_edge(user, src_ip, action="from", timestamp=ts, log_id=lid)
        # src_ip -> host ('connect')
        G.add_edge(src_ip, host, action="connect", timestamp=ts, log_id=lid)

    if len(G) == 0:
        return {"nodes": [], "edges": []}

    # 2. Extract Chain Entities and Sensitive/Target Entities
    chain_entities: Set[str] = set()
    raw_entities = chain.get("entities")
    if isinstance(raw_entities, dict):
        for val in raw_entities.values():
            if isinstance(val, (list, set, tuple)):
                chain_entities.update(str(x) for x in val)

    for s in chain.get("stages", []):
        if s.get("user"):
            chain_entities.add(str(s["user"]))
        if s.get("src_ip"):
            chain_entities.add(str(s["src_ip"]))
        if s.get("host"):
            chain_entities.add(str(s["host"]))
        if s.get("resource"):
            chain_entities.add(str(s["resource"]))

    # Blue nodes: sensitive resources and target hosts
    blue_nodes: Set[str] = set()
    if isinstance(raw_entities, dict):
        resources = raw_entities.get("resources", [])
        blue_nodes.update(str(x) for x in resources)

        hosts = raw_entities.get("hosts", [])
        if len(hosts) > 1:
            blue_nodes.add(str(hosts[-1]))

    # Target host from the last stage if different from initial host
    stages = chain.get("stages", [])
    if stages:
        last_stage = stages[-1]
        last_lids = set(str(x) for x in last_stage.get("log_ids", []))
        s1_lids = set(str(x) for x in stages[0].get("log_ids", []))
        s1_hosts = {str(r.get("host")) for r in logs if str(r.get("log_id")) in s1_lids and r.get("host")}

        for r in logs:
            if str(r.get("log_id")) in last_lids:
                if r.get("resource"):
                    blue_nodes.add(str(r["resource"]))
                if r.get("host") and str(r["host"]) not in s1_hosts:
                    blue_nodes.add(str(r["host"]))

    # 3. Analytics: Patient Zero and Final Target
    patient_zero = None
    final_target = None

    if stages:
        s1 = stages[0]
        # Candidate entities for patient zero: user or IP
        cand_user = str(s1.get("user") or "")
        cand_ip = str(s1.get("src_ip") or "")
        patient_zero_candidates = [c for c in [cand_user, cand_ip] if c and c in G]

        # Final target: resource of the last stage
        s_last = stages[-1]
        if s_last.get("resource") and str(s_last["resource"]) in G:
            final_target = str(s_last["resource"])
        else:
            last_lids = set(str(x) for x in s_last.get("log_ids", []))
            for r in logs:
                if str(r.get("log_id")) in last_lids and r.get("resource"):
                    res = str(r["resource"])
                    if res in G:
                        final_target = res
                        break
            if not final_target and isinstance(raw_entities, dict):
                res_list = raw_entities.get("resources", [])
                if res_list and str(res_list[-1]) in G:
                    final_target = str(res_list[-1])

    # 4. Analytics: Attack Path via nx.shortest_path on nx.DiGraph(G)
    di_G = nx.DiGraph(G)
    attack_path_pairs: Set[tuple] = set()
    chain_log_ids = {str(lid) for s in stages for lid in s.get("log_ids", [])}

    if stages and patient_zero_candidates and final_target:
        for pz in patient_zero_candidates:
            try:
                path = nx.shortest_path(di_G, source=pz, target=final_target)
                for i in range(len(path) - 1):
                    attack_path_pairs.add((path[i], path[i + 1]))
                patient_zero = pz
                break
            except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXError):
                continue

    # 5. Analytics: Pivot Node via Betweenness Centrality
    centrality = nx.betweenness_centrality(di_G)

    # Consider only chain entities present in G
    chain_candidates = [n for n in G.nodes() if n in chain_entities]
    pivot_node = None
    if chain_candidates:
        pivot_node = max(chain_candidates, key=lambda n: centrality.get(n, 0.0))

    # 6. Colors and Status
    # Priority:
    # 1) gray + status='isolated' if in blocked (gray wins over red)
    # 2) blue if sensitive resource or target host
    # 3) red if in chain.entities
    # 4) green if everything else
    def get_node_color_and_status(n: str):
        if n in blocked_set:
            return "gray", "isolated"
        if n in blue_nodes:
            return "blue", "active"
        if n in chain_entities:
            return "red", "active"
        return "green", "active"

    # 7. Green Neighbors Limiting (at most 8 green nodes)
    green_nodes = [n for n in G.nodes() if get_node_color_and_status(n)[0] == "green"]
    non_green_nodes = [n for n in G.nodes() if get_node_color_and_status(n)[0] != "green"]

    if len(green_nodes) > 8:
        # Prioritize green nodes that have an edge to/from a non-green node
        def green_priority(gn):
            degree_with_chain = sum(
                1 for ng in non_green_nodes if G.has_edge(gn, ng) or G.has_edge(ng, gn)
            )
            return degree_with_chain

        green_sorted = sorted(green_nodes, key=green_priority, reverse=True)
        allowed_green = set(green_sorted[:8])
        visible_nodes = set(non_green_nodes) | allowed_green
    else:
        visible_nodes = set(G.nodes())

    # 8. Export to GRAPH contract
    nodes_out = []
    for n in visible_nodes:
        color, status = get_node_color_and_status(n)
        cent = float(centrality.get(n, 0.0))
        size = float(round(20.0 + 60.0 * cent, 2))
        is_piv = (n == pivot_node)

        nodes_out.append(
            {
                "id": str(n),
                "label": str(n),
                "type": node_types.get(n, "resource"),
                "color": color,
                "status": status,
                "is_pivot": is_piv,
                "size": size,
            }
        )

    # Sort nodes consistently by id
    nodes_out.sort(key=lambda x: x["id"])

    edges_out = []
    # Iterate over MultiDiGraph edges
    for u, v, data in G.edges(data=True):
        if u not in visible_nodes or v not in visible_nodes:
            continue

        lid = str(data.get("log_id", ""))
        on_path = (lid in chain_log_ids) or ((u, v) in attack_path_pairs)

        edges_out.append(
            {
                "source": str(u),
                "target": str(v),
                "action": str(data.get("action", "")),
                "timestamp": str(data.get("timestamp", "")),
                "log_id": lid,
                "on_attack_path": bool(on_path),
            }
        )

    return {"nodes": nodes_out, "edges": edges_out}
