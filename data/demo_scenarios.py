"""
Demo Scenarios Centralized Data Store.
Combines scenario metrics, metadata, and graph topology models.
"""

from typing import Dict, Any, List
from data.graph_demo_data import (
    CLEAN_GRAPH,
    USB_EXFILTRATION_GRAPH,
    LATERAL_MOVEMENT_GRAPH,
    get_graph_for_scenario
)

DEMO_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "clean_logs": {
        "id": "clean_logs",
        "name": "Clean Logs",
        "label": "Scenario 0: Clean Logs",
        "badge": "NORMAL // BASELINE",
        "severity": "LOW",
        "description": "Normal enterprise network and host activity with no detected adversary presence.",
        "details": "Routine DNS queries, standard HTTPS web traffic, periodic Active Directory Kerberos ticket requests, and scheduled system maintenance tasks.",
        "metrics": {
            "total_logs": "1,240",
            "benign_logs": "1,240",
            "attack_chains": "0",
            "threat_level": "LOW"
        },
        "raw_logs_count": 1240,
        "nodes": CLEAN_GRAPH["nodes"],
        "edges": CLEAN_GRAPH["edges"],
        "attack_chains": []
    },
    "usb_exfiltration": {
        "id": "usb_exfiltration",
        "name": "USB Exfiltration",
        "label": "Scenario 1: USB Exfiltration",
        "badge": "HIGH // T1052.001",
        "severity": "HIGH",
        "description": "Unauthorized physical removable storage device connected with mass file staging and exfiltration.",
        "details": "Unapproved Kingston USB device mounted on Finance-PC. Rapid staging of sensitive .xlsx and .pdf files followed by archive creation and copy operations.",
        "metrics": {
            "total_logs": "1,486",
            "benign_logs": "1,462",
            "attack_chains": "1",
            "threat_level": "HIGH"
        },
        "raw_logs_count": 1486,
        "nodes": USB_EXFILTRATION_GRAPH["nodes"],
        "edges": USB_EXFILTRATION_GRAPH["edges"],
        "attack_chains": [
            {
                "id": "CHAIN-01",
                "name": "Removable Media Exfiltration",
                "ttp": "T1052.001",
                "source": "Finance-PC",
                "target": "USB Drive (E:)",
                "status": "Active Triage"
            }
        ]
    },
    "lateral_movement": {
        "id": "lateral_movement",
        "name": "Lateral Movement",
        "label": "Scenario 2: Lateral Movement",
        "badge": "CRITICAL // T1021.002",
        "severity": "CRITICAL",
        "description": "Multi-host intrusion with credential dumping, Pass-the-Hash, and pivot toward Domain Controller.",
        "details": "Initial breach on DMZ Web-Server, LSASS memory dump via Mimikatz, Pass-the-Hash authentication across Admin subnets, and remote service creation on DC-01.",
        "metrics": {
            "total_logs": "1,942",
            "benign_logs": "1,885",
            "attack_chains": "3",
            "threat_level": "CRITICAL"
        },
        "raw_logs_count": 1942,
        "nodes": LATERAL_MOVEMENT_GRAPH["nodes"],
        "edges": LATERAL_MOVEMENT_GRAPH["edges"],
        "attack_chains": [
            {"id": "CHAIN-01", "name": "Initial DMZ C2 Ingress", "ttp": "T1071.001", "status": "Established"},
            {"id": "CHAIN-02", "name": "Credential Access (LSASS)", "ttp": "T1003.001", "status": "Completed"},
            {"id": "CHAIN-03", "name": "SMB Lateral Movement to DC", "ttp": "T1021.002", "status": "Critical Breach"}
        ]
    }
}

def get_demo_scenario(scenario_id: str) -> Dict[str, Any]:
    """Returns the scenario data dictionary for a given scenario ID."""
    return DEMO_SCENARIOS.get(scenario_id, DEMO_SCENARIOS["clean_logs"])

def get_all_scenario_ids() -> list:
    """Returns list of all available scenario identifiers."""
    return list(DEMO_SCENARIOS.keys())
