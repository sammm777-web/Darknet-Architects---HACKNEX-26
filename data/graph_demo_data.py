"""
Demo Graph Data Structures for Attack Path & Network Topology.
Provides standardized nodes and edges for:
1. Clean Logs (Normal baseline activity)
2. USB Exfiltration (Sensitive file copy to removable media)
3. Lateral Movement (Credential dumping & pivot across network)
"""

from typing import Dict, Any, List

# -------------------------------------------------------------------------
# SCENARIO 0: CLEAN LOGS (Normal activity)
# -------------------------------------------------------------------------
CLEAN_GRAPH: Dict[str, Any] = {
    "name": "Clean Logs",
    "description": "Normal enterprise baseline activity with no malicious intrusion.",
    "nodes": [
        {
            "id": "usr-alice",
            "label": "alice.sec",
            "type": "USER",
            "status": "NORMAL",
            "risk": "LOW",
            "ip": "10.0.1.15",
            "device": "WS-ALPHA",
            "role": "Security Analyst",
            "first_seen": "08:15:22",
            "last_activity": "09:42:10"
        },
        {
            "id": "wkst-01",
            "label": "WS-ALPHA (10.0.1.15)",
            "type": "DEVICE",
            "status": "SAFE",
            "risk": "LOW",
            "ip": "10.0.1.15",
            "device": "WS-ALPHA",
            "os": "Windows 11 Enterprise",
            "first_seen": "08:00:00",
            "last_activity": "09:42:10"
        },
        {
            "id": "dc-01",
            "label": "Domain Controller (10.0.0.5)",
            "type": "SERVER",
            "status": "SAFE",
            "risk": "LOW",
            "ip": "10.0.0.5",
            "device": "DC-01",
            "service": "Active Directory / Kerberos",
            "first_seen": "00:00:01",
            "last_activity": "09:45:00"
        },
        {
            "id": "file-srv",
            "label": "File Server (10.0.0.22)",
            "type": "SERVER",
            "status": "SAFE",
            "risk": "LOW",
            "ip": "10.0.0.22",
            "device": "SRV-FILE-01",
            "service": "SMB File Share",
            "first_seen": "00:00:01",
            "last_activity": "09:41:50"
        },
        {
            "id": "doc-budget",
            "label": "Quarterly_Budget.xlsx",
            "type": "FILE",
            "status": "SAFE",
            "risk": "LOW",
            "ip": "10.0.0.22",
            "device": "SRV-FILE-01",
            "path": "\\\\FileServer\\Finance\\Budget.xlsx",
            "first_seen": "09:30:00",
            "last_activity": "09:41:50"
        }
    ],
    "edges": [
        {
            "source": "usr-alice",
            "target": "wkst-01",
            "label": "LOGIN (Kerberos)",
            "type": "LOGIN",
            "status": "BENIGN"
        },
        {
            "source": "wkst-01",
            "target": "dc-01",
            "label": "AUTH_TGS (Port 88)",
            "type": "ACCESS",
            "status": "BENIGN"
        },
        {
            "source": "wkst-01",
            "target": "file-srv",
            "label": "SMB_CONNECT (Port 445)",
            "type": "REMOTE CONNECTION",
            "status": "BENIGN"
        },
        {
            "source": "file-srv",
            "target": "doc-budget",
            "label": "FILE READ (Standard)",
            "type": "FILE ACCESS",
            "status": "BENIGN"
        }
    ]
}

# -------------------------------------------------------------------------
# SCENARIO 1: USB EXFILTRATION (Removable media data transfer)
# -------------------------------------------------------------------------
USB_EXFILTRATION_GRAPH: Dict[str, Any] = {
    "name": "USB Exfiltration",
    "description": "Suspicious mass file staging and unauthorized data transfer to removable USB storage.",
    "nodes": [
        {
            "id": "usr-john",
            "label": "john.doe",
            "type": "USER",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "192.168.1.42",
            "device": "WS-042",
            "role": "Finance Clerk",
            "first_seen": "10:32:14",
            "last_activity": "10:38:51"
        },
        {
            "id": "wkst-042",
            "label": "WS-042 (192.168.1.42)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "192.168.1.42",
            "device": "WS-042",
            "os": "Windows 10 Workstation",
            "first_seen": "10:30:00",
            "last_activity": "10:38:55"
        },
        {
            "id": "doc-sensitive",
            "label": "financial_records.xlsx",
            "type": "FILE",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "192.168.1.42",
            "device": "WS-042",
            "path": "C:\\Users\\john\\Documents\\Confidential\\financial_records.xlsx",
            "first_seen": "10:35:12",
            "last_activity": "10:37:40"
        },
        {
            "id": "usb-042",
            "label": "USB-042 (Removable E:)",
            "type": "USB DEVICE",
            "status": "MALICIOUS",
            "risk": "CRITICAL",
            "ip": "192.168.1.42",
            "device": "WS-042",
            "serial": "KNGSTN-8842-EXFIL",
            "first_seen": "10:36:05",
            "last_activity": "10:38:51"
        },
        {
            "id": "ext-drop",
            "label": "Physical Drop Egress",
            "type": "ATTACKER",
            "status": "MALICIOUS",
            "risk": "CRITICAL",
            "ip": "External / Offline",
            "device": "Removable Flash Drive",
            "target": "Physical Drive Egress / Offsite Drop",
            "first_seen": "10:38:51",
            "last_activity": "10:38:51"
        }
    ],
    "edges": [
        {
            "source": "usr-john",
            "target": "wkst-042",
            "label": "LOGIN (Interactive)",
            "type": "LOGIN",
            "status": "NORMAL"
        },
        {
            "source": "wkst-042",
            "target": "doc-sensitive",
            "label": "FILE ACCESS (Unapproved)",
            "type": "FILE ACCESS",
            "status": "ATTACK"
        },
        {
            "source": "doc-sensitive",
            "target": "usb-042",
            "label": "TRANSFER (850MB Archive)",
            "type": "TRANSFER",
            "status": "ATTACK"
        },
        {
            "source": "usb-042",
            "target": "ext-drop",
            "label": "EXFILTRATION (Physical Egress)",
            "type": "EXFILTRATION",
            "status": "ATTACK"
        }
    ]
}

# -------------------------------------------------------------------------
# SCENARIO 2: LATERAL MOVEMENT (Adversary pivoting across enterprise)
# -------------------------------------------------------------------------
LATERAL_MOVEMENT_GRAPH: Dict[str, Any] = {
    "name": "Lateral Movement",
    "description": "Multi-stage attack involving credential dumping, Pass-the-Hash, and pivoting to Domain Controller.",
    "nodes": [
        {
            "id": "attacker-c2",
            "label": "Attacker C2 (198.51.100.42)",
            "type": "ATTACKER",
            "status": "MALICIOUS",
            "risk": "CRITICAL",
            "ip": "198.51.100.42",
            "device": "C2 Server (Cobalt Strike)",
            "infrastructure": "Cobalt Strike Team Server",
            "first_seen": "03:12:08",
            "last_activity": "03:45:19"
        },
        {
            "id": "wkst-compromised",
            "label": "Compromised WS (10.0.1.12)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "10.0.1.12",
            "device": "WS-FIN-012",
            "initial_vector": "Phishing / Reverse Shell (Port 443)",
            "first_seen": "03:14:22",
            "last_activity": "03:44:00"
        },
        {
            "id": "usr-compromised",
            "label": "admin.svc (Harvested Creds)",
            "type": "USER",
            "status": "COMPROMISED",
            "risk": "CRITICAL",
            "ip": "10.0.1.12",
            "device": "WS-FIN-012",
            "privilege": "Local Administrator / Tier-1",
            "first_seen": "03:22:15",
            "last_activity": "03:44:30"
        },
        {
            "id": "srv-internal",
            "label": "App Middleware (10.0.0.14)",
            "type": "SERVER",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "10.0.0.14",
            "device": "SRV-APP-01",
            "role": "Application Middleware",
            "first_seen": "03:30:45",
            "last_activity": "03:43:10"
        },
        {
            "id": "wkst-second",
            "label": "Jumpbox WS (10.0.1.99)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "risk": "HIGH",
            "ip": "10.0.1.99",
            "device": "WS-MGMT-99",
            "role": "Management Jumpbox",
            "first_seen": "03:36:12",
            "last_activity": "03:44:50"
        },
        {
            "id": "dc-crown-jewel",
            "label": "Primary DC-01 (10.0.0.5)",
            "type": "SERVER",
            "status": "TARGET",
            "risk": "CRITICAL",
            "ip": "10.0.0.5",
            "device": "DC-CORP-01",
            "role": "Active Directory Crown Jewel",
            "first_seen": "00:00:01",
            "last_activity": "03:45:19"
        }
    ],
    "edges": [
        {
            "source": "attacker-c2",
            "target": "wkst-compromised",
            "label": "REMOTE CONNECTION (C2 Beacon)",
            "type": "REMOTE CONNECTION",
            "status": "ATTACK"
        },
        {
            "source": "wkst-compromised",
            "target": "usr-compromised",
            "label": "CREDENTIAL ACCESS (LSASS Dump)",
            "type": "ACCESS",
            "status": "ATTACK"
        },
        {
            "source": "usr-compromised",
            "target": "srv-internal",
            "label": "REMOTE LOGIN (WMI Exec)",
            "type": "LOGIN",
            "status": "ATTACK"
        },
        {
            "source": "srv-internal",
            "target": "wkst-second",
            "label": "LATERAL MOVEMENT (Pass-the-Hash)",
            "type": "LATERAL MOVEMENT",
            "status": "ATTACK"
        },
        {
            "source": "wkst-second",
            "target": "dc-crown-jewel",
            "label": "LATERAL MOVEMENT (PsExec SMB 445)",
            "type": "LATERAL MOVEMENT",
            "status": "ATTACK"
        }
    ]
}

# Mapping registry
SCENARIO_GRAPHS: Dict[str, Dict[str, Any]] = {
    "clean_logs": CLEAN_GRAPH,
    "usb_exfiltration": USB_EXFILTRATION_GRAPH,
    "lateral_movement": LATERAL_MOVEMENT_GRAPH
}

def get_graph_for_scenario(scenario_id: str) -> Dict[str, Any]:
    """
    Retrieves standardized graph topology data (nodes and edges)
    for a given scenario identifier.
    """
    return SCENARIO_GRAPHS.get(scenario_id, CLEAN_GRAPH)
