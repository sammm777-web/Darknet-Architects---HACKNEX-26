"""
backend/ai_explainer.py

AI threat intelligence reasoning and evidence verification.
Combines deterministic risk scoring, an evidence firewall, OpenAI API incident
reporting with automatic retry and template fallback, and persistent caching.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Ensure workspace root is in sys.path when executed directly
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.graph_builder import build_graph

# -----------------------------------------------------------------------------
# Constants & Configuration
# -----------------------------------------------------------------------------

MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """You are a senior SOC analyst writing a forensic incident report.
You receive one attack chain and the raw log rows that make it up.
RULES:
1. Use ONLY the provided log rows. Never invent events, IPs, users, or times.
2. Write exactly one entry per stage, in order, and cite the log_id values and timestamps from the rows that prove that stage.
3. Use the risk_score and risk_rationale given to you. Do not change them.
4. Recommendations must use ONLY these actions matching target by type: block_ip (target in chain IP addresses), revoke_user_token (target in chain usernames), isolate_host (target in chain hostnames), reset_credentials (target in chain usernames).
5. Return ONLY JSON with keys: summary, risk_score, risk_rationale, stages, recommendations.
   stages must be a list of objects with keys: stage_no, log_ids, timestamps, explanation.
   recommendations must be a list of objects with keys: action, target, why."""

WEIGHTS: Dict[str, int] = {
    "per_stage": 20,
    "exfiltration": 20,
    "privilege_escalation": 15,
    "lateral_movement": 15,
}

ALLOWED_ACTIONS: Set[str] = {
    "block_ip",
    "revoke_user_token",
    "isolate_host",
    "reset_credentials",
}


# -----------------------------------------------------------------------------
# Lazy OpenAI Client
# -----------------------------------------------------------------------------


def get_openai_client():
    """
    Lazy-creates the OpenAI client so importing this module never fails
    if OPENAI_API_KEY is not configured.
    """
    from dotenv import load_dotenv
    from openai import OpenAI

    load_dotenv()
    return OpenAI()


# -----------------------------------------------------------------------------
# Deterministic Scoring & Labels
# -----------------------------------------------------------------------------


def severity_label(score: int) -> str:
    """Returns human-readable severity label matching SOC thresholds."""
    if score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def compute_risk(chain: Dict[str, Any], logs: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes a deterministic, explainable risk score and rationale string.

    Rules:
    - 20 points per stage (+20 * n)
    - +20 if tactic 'Exfiltration' is observed
    - +15 if tactic 'Privilege Escalation' is observed
    - +15 if tactic 'Lateral Movement' is observed
    - Capped at 100
    """
    chain = chain or {}
    stages = chain.get("stages", []) or []
    n = len(stages)

    score = 0
    why: List[str] = []

    # Per-stage contribution
    stage_pts = WEIGHTS["per_stage"] * n
    score += stage_pts
    why.append(f"{n} linked attack stages (+{stage_pts})")

    tactics = {str(s.get("tactic")) for s in stages if s.get("tactic")}

    if "Exfiltration" in tactics:
        exfil_pts = WEIGHTS["exfiltration"]
        score += exfil_pts
        why.append(f"data exfiltration (+{exfil_pts})")

    if "Privilege Escalation" in tactics:
        priv_pts = WEIGHTS["privilege_escalation"]
        score += priv_pts
        why.append(f"privilege escalation (+{priv_pts})")

    if "Lateral Movement" in tactics:
        lat_pts = WEIGHTS["lateral_movement"]
        score += lat_pts
        why.append(f"lateral movement across hosts (+{lat_pts})")

    capped_score = min(100, score)
    rationale = "; ".join(why)
    return capped_score, rationale


# -----------------------------------------------------------------------------
# Evidence Firewall
# -----------------------------------------------------------------------------


def validate_citations(report: Any, chain: Any, logs: Any) -> bool:
    """
    Evidence firewall. Returns True ONLY if:
    - every cited log_id exists in logs
    - every stage has at least one log_id
    - stage count equals chain stage count and stage_no values are 1..n in order
    - every cited log_id belongs to the chain stage it is attached to
    - every string in a report stage's timestamps equals the str(timestamp) of one of the log rows cited by that same stage
    - every recommendation action is one of the four allowed, and action & target match by type:
        * block_ip target in chain.entities.ips
        * revoke_user_token and reset_credentials target in chain.entities.users
        * isolate_host target in chain.entities.hosts

    Never raises on malformed input (returns False).
    """
    try:
        if not isinstance(report, dict) or not isinstance(chain, dict) or not isinstance(logs, list):
            return False

        # 1. Lookup of all valid log_ids in logs
        valid_log_ids = set()
        for r in logs:
            if isinstance(r, dict) and "log_id" in r:
                valid_log_ids.add(str(r["log_id"]))

        # 2. Extract allowed targets from chain entities by type
        raw_entities = chain.get("entities")
        if not isinstance(raw_entities, dict):
            return False

        ips = {str(x) for x in raw_entities.get("ips", [])} if isinstance(raw_entities.get("ips"), (list, set, tuple)) else set()
        users = {str(x) for x in raw_entities.get("users", [])} if isinstance(raw_entities.get("users"), (list, set, tuple)) else set()
        hosts = {str(x) for x in raw_entities.get("hosts", [])} if isinstance(raw_entities.get("hosts"), (list, set, tuple)) else set()

        # 3. Stages comparison
        chain_stages = chain.get("stages", [])
        if not isinstance(chain_stages, list):
            return False

        report_stages = report.get("stages", [])
        if not isinstance(report_stages, list):
            return False

        # Stage count must match exactly
        if len(report_stages) != len(chain_stages):
            return False

        # stage_no values must be 1..n in order
        expected_stage_nos = list(range(1, len(chain_stages) + 1))
        actual_stage_nos = [s.get("stage_no") for s in report_stages if isinstance(s, dict)]
        if actual_stage_nos != expected_stage_nos:
            return False

        for r_stage, c_stage in zip(report_stages, chain_stages):
            if not isinstance(r_stage, dict) or not isinstance(c_stage, dict):
                return False

            r_lids = r_stage.get("log_ids", [])
            if not isinstance(r_lids, list) or len(r_lids) == 0:
                # Every stage must have at least one log_id
                return False

            c_lids_raw = c_stage.get("log_ids", [])
            c_lids = {str(x) for x in c_lids_raw} if isinstance(c_lids_raw, list) else set()

            for lid in r_lids:
                lid_str = str(lid)
                # Every cited log_id must exist in logs
                if lid_str not in valid_log_ids:
                    return False
                # Every cited log_id must belong to this specific chain stage
                if lid_str not in c_lids:
                    return False

            # Check 3b: Every string in a report stage's timestamps must equal the
            # str(timestamp) of one of the log rows cited by that same stage. Compare as strings.
            r_timestamps = r_stage.get("timestamps", [])
            if not isinstance(r_timestamps, list):
                return False

            stage_cited_lids = {str(x) for x in r_lids}
            cited_log_timestamps = {
                str(r["timestamp"])
                for r in logs
                if isinstance(r, dict) and str(r.get("log_id")) in stage_cited_lids and "timestamp" in r
            }

            for ts in r_timestamps:
                if not isinstance(ts, str):
                    return False
                if ts not in cited_log_timestamps:
                    return False

        # 4. Recommendations check (Check 3a: action and target must match by type)
        recs = report.get("recommendations", [])
        if not isinstance(recs, list):
            return False

        for rec in recs:
            if not isinstance(rec, dict):
                return False
            action = rec.get("action")
            target = rec.get("target")
            if not isinstance(target, str):
                return False

            if action == "block_ip":
                if target not in ips:
                    return False
            elif action in ("revoke_user_token", "reset_credentials"):
                if target not in users:
                    return False
            elif action == "isolate_host":
                if target not in hosts:
                    return False
            else:
                return False

        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Template Report Fallback
# -----------------------------------------------------------------------------


def template_report(chain: Dict[str, Any], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Constructs a complete forensic incident REPORT using rule-based templates.
    No LLM or network calls required.
    """
    chain = chain or {}
    logs = logs or []
    chain_id = str(chain.get("chain_id", "UNKNOWN"))
    stages = chain.get("stages", []) or []

    score, rationale = compute_risk(chain, logs)
    sev = severity_label(score)

    # Build log lookup map
    log_map: Dict[str, Dict[str, Any]] = {}
    for r in logs:
        if isinstance(r, dict) and "log_id" in r:
            log_map[str(r["log_id"])] = r

    # Build stages
    report_stages: List[Dict[str, Any]] = []
    for idx, s in enumerate(stages):
        stage_no = idx + 1
        tactic = str(s.get("tactic", "Unknown Tactic"))
        lids = [str(x) for x in s.get("log_ids", [])]

        timestamps: List[str] = []
        for lid in lids:
            if lid in log_map and log_map[lid].get("timestamp"):
                timestamps.append(str(log_map[lid]["timestamp"]))
        if not timestamps and s.get("timestamp"):
            timestamps.append(str(s["timestamp"]))

        user = str(s.get("user") or (log_map[lids[0]].get("user") if lids and lids[0] in log_map else "unknown"))
        src_ip = str(s.get("src_ip") or (log_map[lids[0]].get("src_ip") if lids and lids[0] in log_map else "unknown"))

        explanation = (
            f"Stage {stage_no} ({tactic}): User '{user}' executed actions from '{src_ip}' "
            f"evidenced by log event(s) {', '.join(lids)} at {', '.join(timestamps)}."
        )

        report_stages.append(
            {
                "stage_no": stage_no,
                "log_ids": lids,
                "timestamps": timestamps,
                "explanation": explanation,
            }
        )

    # Recommendations derived by rule
    tactics = {str(s.get("tactic")) for s in stages if s.get("tactic")}
    entities = chain.get("entities", {}) if isinstance(chain.get("entities"), dict) else {}
    users = [str(x) for x in entities.get("users", [])]
    ips = [str(x) for x in entities.get("ips", [])]
    hosts = [str(x) for x in entities.get("hosts", [])]

    recommendations: List[Dict[str, Any]] = []

    # Rule: exfiltration -> block_ip on the chain IP
    if "Exfiltration" in tactics and ips:
        target_ip = ips[0]
        recommendations.append(
            {
                "action": "block_ip",
                "target": target_ip,
                "why": f"Block ingress and egress network traffic from source IP {target_ip} to halt data exfiltration.",
            }
        )

    # Rule: privilege escalation -> revoke_user_token
    if "Privilege Escalation" in tactics and users:
        target_user = users[0]
        recommendations.append(
            {
                "action": "revoke_user_token",
                "target": target_user,
                "why": f"Revoke active OAuth and Kerberos session tokens for compromised identity {target_user}.",
            }
        )

    # Rule: lateral movement -> isolate_host
    if "Lateral Movement" in tactics and hosts:
        target_host = hosts[-1] if len(hosts) > 1 else hosts[0]
        recommendations.append(
            {
                "action": "isolate_host",
                "target": target_host,
                "why": f"Quarantine endpoint {target_host} from the network to prevent further lateral movement.",
            }
        )

    # Rule: always reset_credentials for the first user
    if users:
        primary_user = users[0]
        recommendations.append(
            {
                "action": "reset_credentials",
                "target": primary_user,
                "why": f"Enforce immediate credential and password reset for primary compromised account {primary_user}.",
            }
        )

    summary = (
        f"Incident Report for {chain_id}: An adversary campaign comprising {len(stages)} correlated attack stages "
        f"was detected. Assessed Threat Level: {sev.upper()} (Risk Score: {score}/100). Containment actions required."
    )

    report = {
        "summary": summary,
        "risk_score": score,
        "risk_rationale": rationale,
        "stages": report_stages,
        "recommendations": recommendations,
        "citations_verified": False,
    }

    report["citations_verified"] = bool(validate_citations(report, chain, logs))
    return report


# -----------------------------------------------------------------------------
# AI Report Generation
# -----------------------------------------------------------------------------


def ai_report(
    chain: Dict[str, Any],
    logs: List[Dict[str, Any]],
    score: int,
    rationale: str,
) -> Dict[str, Any]:
    """
    Invokes OpenAI chat completion to generate a forensic report from chain logs.
    Sends ONLY the chain's supporting log rows plus deterministic score and rationale.
    Overwrites the model's score and rationale with deterministic values.
    """
    client = get_openai_client()

    # Send ONLY the chain's log rows (never unrelated logs)
    chain_lids = {str(lid) for s in chain.get("stages", []) for lid in s.get("log_ids", [])}
    chain_logs = [r for r in logs if str(r.get("log_id")) in chain_lids]

    payload = {
        "chain": chain,
        "logs": chain_logs,
        "risk_score": score,
        "risk_rationale": rationale,
    }

    resp = client.chat.completions.create(
        model=MODEL,
        temperature=0,
        response_format={"type": "json_object"},
        timeout=15.0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, default=str)},
        ],
    )

    raw_json = resp.choices[0].message.content
    report = json.loads(raw_json)

    # Overwrite model's score and rationale with deterministic values
    report["risk_score"] = score
    report["risk_rationale"] = rationale
    return report


# -----------------------------------------------------------------------------
# Threat Intelligence Orchestrator (Cache -> AI -> Retry -> Template)
# -----------------------------------------------------------------------------


def generate_threat_intelligence(
    incident: Dict[str, Any],
    cache_dir: Union[str, Path] = "cache",
) -> Dict[str, Any]:
    """
    End-to-end pipeline:
    1. Cache hit -> validate cached report. If valid, return it. If invalid, ignore and regenerate.
    2. Else AI call -> validate. If invalid, retry exactly once.
    3. If still invalid or any exception (no key, timeout, offline) -> template_report.
    4. Set report['citations_verified'].
    5. Write to cache ONLY if the report passed validation AND source is 'ai'
       (template reports are not written to cache, so a later online run can replace them with a real AI report).
    6. Set report['source'] in {'cache', 'ai', 'template'}.
    7. Generate graph via build_graph(chain, logs, blocked).
    """
    incident = incident or {}
    chain = incident.get("chain", {})
    logs = incident.get("logs", [])
    blocked = incident.get("blocked", set())

    chain_id = str(chain.get("chain_id", "UNKNOWN"))
    cache_path = Path(cache_dir) / f"{chain_id}.json"

    report: Optional[Dict[str, Any]] = None
    report_source: Optional[str] = None

    # Step 1: Cache hit check
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached_candidate = json.load(f)
            if validate_citations(cached_candidate, chain, logs):
                report = cached_candidate
                report_source = "cache"
            else:
                report = None
                report_source = None
        except Exception:
            report = None
            report_source = None

    # Step 2: Generation if not cached
    if report is None:
        score, rationale = compute_risk(chain, logs)
        try:
            candidate = ai_report(chain, logs, score, rationale)
            if validate_citations(candidate, chain, logs):
                report = candidate
                report_source = "ai"
            else:
                # Retry exactly once
                candidate_retry = ai_report(chain, logs, score, rationale)
                if validate_citations(candidate_retry, chain, logs):
                    report = candidate_retry
                    report_source = "ai"
                else:
                    report = template_report(chain, logs)
                    report_source = "template"
        except Exception:
            # Fallback on any exception (timeout, no key, no internet, json error)
            report = template_report(chain, logs)
            report_source = "template"

    # Step 3: Verification flag and source
    is_valid = validate_citations(report, chain, logs)
    report["citations_verified"] = is_valid
    report["source"] = report_source

    # Step 4: Write to cache ONLY if the final report passed validation AND source is 'ai'
    if is_valid and report_source == "ai":
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        except Exception:
            pass

    # Step 5: Build Graph
    context_logs = incident.get("context_logs")
    graph = build_graph(chain, logs, blocked=blocked, context_logs=context_logs)

    return {"graph": graph, "report": report}


# -----------------------------------------------------------------------------
# CLI: Pre-generate Caches
# -----------------------------------------------------------------------------


def main():
    import argparse

    parser = argparse.ArgumentParser(description="ChainSight Threat Intelligence CLI")
    parser.add_argument(
        "--pregenerate",
        action="store_true",
        help="Pre-generate cached reports for all mock scenarios",
    )
    args = parser.parse_args()

    if args.pregenerate:
        root = Path(__file__).resolve().parent.parent
        chains_path = root / "data" / "mock_chains.json"
        logs_path = root / "data" / "mock_logs.json"
        cache_path = root / "cache"

        if not chains_path.exists() or not logs_path.exists():
            print(f"Error: Required mock data missing at {chains_path} or {logs_path}")
            sys.exit(1)

        with open(chains_path, "r", encoding="utf-8") as f:
            chains = json.load(f)
        with open(logs_path, "r", encoding="utf-8") as f:
            logs = json.load(f)

        cache_path.mkdir(parents=True, exist_ok=True)

        for chain in chains:
            cid = chain.get("chain_id")
            # Extract logs for this chain
            chain_lids = {str(lid) for s in chain.get("stages", []) for lid in s.get("log_ids", [])}
            incident_logs = [r for r in logs if str(r.get("log_id")) in chain_lids or r.get("chain_id") == cid]

            incident = {
                "chain": chain,
                "logs": incident_logs,
                "blocked": {"203.0.113.199"} if cid == "C-1" else set(),
            }
            out = generate_threat_intelligence(incident, cache_dir=cache_path)
            rep = out["report"]
            print(f"[{cid}] source: {rep.get('source')} | citations_verified: {rep.get('citations_verified')}")


if __name__ == "__main__":
    main()
