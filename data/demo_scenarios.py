"""
Demo Scenarios Centralized Data Store.
Provides standardized cybersecurity scenario data structures.
Expandable for future Graph (PyVis) and Detection Engine integrations.
"""

from typing import Dict, Any

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
        "nodes": [
            {"id": "usr-wkst-01", "label": "Workstation-01 (10.0.1.15)", "type": "host", "status": "safe"},
            {"id": "usr-wkst-02", "label": "Workstation-02 (10.0.1.18)", "type": "host", "status": "safe"},
            {"id": "dc-srv-01", "label": "Domain Controller (10.0.0.5)", "type": "server", "status": "safe"},
            {"id": "mail-srv-01", "label": "Mail Gateway (10.0.0.8)", "type": "server", "status": "safe"}
        ],
        "edges": [
            {"from": "usr-wkst-01", "to": "dc-srv-01", "label": "Kerberos TGS Request (Port 88)", "type": "benign"},
            {"from": "usr-wkst-02", "to": "mail-srv-01", "label": "IMAPS / TLS (Port 993)", "type": "benign"}
        ],
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
        "nodes": [
            {"id": "fin-wkst-04", "label": "Finance-PC (10.0.2.45)", "type": "host", "status": "compromised"},
            {"id": "usb-dev-01", "label": "Removable USB Drive (E:)", "type": "storage", "status": "malicious"},
            {"id": "file-srv-01", "label": "Financial Share (10.0.0.22)", "type": "server", "status": "targeted"}
        ],
        "edges": [
            {"from": "fin-wkst-04", "to": "usb-dev-01", "label": "Mass Copy (24 docs, 850MB)", "type": "exfiltration"},
            {"from": "fin-wkst-04", "to": "file-srv-01", "label": "SMB Volume Access (Confidential)", "type": "suspicious"}
        ],
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
        "nodes": [
            {"id": "dmz-web-01", "label": "Web Server DMZ (192.168.10.12)", "type": "server", "status": "compromised"},
            {"id": "adm-wkst-09", "label": "Admin Station (10.0.1.99)", "type": "host", "status": "compromised"},
            {"id": "dc-srv-01", "label": "Primary DC-01 (10.0.0.5)", "type": "server", "status": "compromised"},
            {"id": "c2-external", "label": "Attacker C2 (198.51.100.42)", "type": "external", "status": "malicious"}
        ],
        "edges": [
            {"from": "c2-external", "to": "dmz-web-01", "label": "Reverse HTTPS Shell (Port 443)", "type": "c2"},
            {"from": "dmz-web-01", "to": "adm-wkst-09", "label": "PsExec / SMB Lateral (Port 445)", "type": "lateral"},
            {"from": "adm-wkst-09", "to": "dc-srv-01", "label": "Pass-the-Hash Kerberos (Port 88)", "type": "lateral"}
        ],
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
