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
            "ip": "10.0.1.15",
            "role": "Security Analyst"
        },
        {
            "id": "wkst-01",
            "label": "WS-ALPHA (10.0.1.15)",
            "type": "DEVICE",
            "status": "SAFE",
            "os": "Windows 11 Enterprise"
        },
        {
            "id": "dc-01",
            "label": "Domain Controller (10.0.0.5)",
            "type": "SERVER",
            "status": "SAFE",
            "service": "Active Directory / Kerberos"
        },
        {
            "id": "file-srv",
            "label": "File Server (10.0.0.22)",
            "type": "SERVER",
            "status": "SAFE",
            "service": "SMB File Share"
        },
        {
            "id": "doc-budget",
            "label": "Quarterly_Budget.xlsx",
            "type": "FILE",
            "status": "SAFE",
            "path": "\\\\FileServer\\Finance\\Budget.xlsx"
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
            "role": "Finance Clerk"
        },
        {
            "id": "wkst-042",
            "label": "WS-042 (10.0.2.45)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "os": "Windows 10 Workstation"
        },
        {
            "id": "doc-sensitive",
            "label": "financial_records.xlsx",
            "type": "FILE",
            "status": "COMPROMISED",
            "path": "C:\\Users\\john\\Documents\\Confidential\\financial_records.xlsx"
        },
        {
            "id": "usb-042",
            "label": "USB-042 (Removable E:)",
            "type": "USB DEVICE",
            "status": "MALICIOUS",
            "serial": "KNGSTN-8842-EXFIL"
        },
        {
            "id": "ext-drop",
            "label": "External Destination",
            "type": "ATTACKER",
            "status": "MALICIOUS",
            "target": "Physical Drive Egress / Offsite Drop"
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
            "label": "Attacker IP (198.51.100.42)",
            "type": "ATTACKER",
            "status": "MALICIOUS",
            "infrastructure": "Cobalt Strike C2 Server"
        },
        {
            "id": "wkst-compromised",
            "label": "Compromised Workstation (10.0.1.12)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "initial_vector": "Phishing / Reverse Shell"
        },
        {
            "id": "usr-compromised",
            "label": "Compromised User (admin.svc)",
            "type": "USER",
            "status": "COMPROMISED",
            "privilege": "Local Administrator"
        },
        {
            "id": "srv-internal",
            "label": "Internal Server (10.0.0.14)",
            "type": "SERVER",
            "status": "COMPROMISED",
            "role": "Application Middleware"
        },
        {
            "id": "wkst-second",
            "label": "Second Workstation (10.0.1.99)",
            "type": "DEVICE",
            "status": "COMPROMISED",
            "role": "Management Jumpbox"
        },
        {
            "id": "dc-crown-jewel",
            "label": "Primary DC-01 (10.0.0.5)",
            "type": "SERVER",
            "status": "TARGET",
            "role": "Active Directory Crown Jewel"
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
