# CyberOrion SOC Evidence Benchmark

- Run: `20260824_061103_soc_evidence_compare_n12_agent`
- Arm: `framework` / mode `agent`
- Model: `deepseek-v4-flash`
- Cases: 12
- Task Success: 0.725
- Evidence Grounding: 0.979
- ATT&CK F1: 0.833

## Failure Taxonomy

- attack_mapping: 2
- unsupported_claim: 1

---
## SOC-008 - Resist misleading benign records

Task success: 0.741
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1110",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host"
  ],
  "claims": [
    {
      "text": "Brute force attack on svc_backup account from 10.24.7.19",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after brute force, indicating account compromise",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Lateral movement via RDP to FIN-WS22 using compromised credentials",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": []
}
```

---
## SOC-006 - Legitimate backup activity with scanner noise

Task success: 0.472
Evidence Grounding: 0.750

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "benign",
  "incident_labels": [
    "expected_activity"
  ],
  "attack_techniques": [],
  "evidence_ids": [
    "E1",
    "E2",
    "E3",
    "N1"
  ],
  "response_actions": [
    "close_alert",
    "document_baseline"
  ],
  "claims": [
    {
      "text": "Activity matches approved maintenance change ticket and backup window.",
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ]
    },
    {
      "text": "Low-confidence scan from authorized vulnerability scanner is consistent with scheduled validation.",
      "evidence_ids": [
        "N1"
      ]
    }
  ],
  "confidence": 0.95,
  "tool_trace": []
}
```

---
## SOC-001 - Service-account password spray

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1110",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Brute force attack on svc_backup succeeded from IP 10.24.7.19.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Attacker used RDP to move laterally to FIN-WS22.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```

---
## SOC-007 - Select reversible containment

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1110",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "The account svc_backup was subjected to a brute-force attack, as evidenced by 42 failed logons before a successful logon from the same source IP.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The successful logon then led to an RDP session to FIN-WS22, indicating lateral movement after credential access.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": []
}
```

---
## SOC-002 - DNS tunnel with staged exfiltration

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "exfiltration",
    "command_and_control"
  ],
  "attack_techniques": [
    "T1048",
    "T1071.004"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "block_domain",
    "preserve_evidence",
    "document_baseline"
  ],
  "claims": [
    {
      "text": "Unusual DNS TXT queries with high-entropy subdomains to sync-cloud.example indicate DNS tunneling for data exfiltration or C2.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "ENG-17 transferred data volume significantly above baseline, confirming data exfiltration.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell compressed archive before the DNS burst suggests preparation of data for exfiltration.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```

---
## SOC-004 - Find the signal in maintenance noise

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1110",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Brute force attack against svc_backup account from 10.24.7.19.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful authentication after brute force indicates account compromise.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Lateral movement to FIN-WS22 via RDP using compromised account.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.8,
  "tool_trace": []
}
```

---
## SOC-009 - OAuth consent followed by mailbox collection

Task success: 0.756
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "exfiltration",
    "persistence"
  ],
  "attack_techniques": [
    "T1528",
    "T1114"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "preserve_evidence",
    "block_domain"
  ],
  "claims": [
    {
      "text": "User approved a third-party OAuth app with broad Mail.Read permissions without verification.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The app accessed a large volume of emails from a new ASN shortly after approval.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "A refresh token continued to work after a password reset, indicating persistence.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.92,
  "tool_trace": []
}
```

---
## SOC-010 - Linux webshell and outbound reverse shell

Task success: 0.756
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "execution",
    "command_and_control",
    "persistence"
  ],
  "attack_techniques": [
    "T1505.003",
    "T1059.004"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "preserve_evidence",
    "block_domain",
    "remove_persistence"
  ],
  "claims": [
    {
      "text": "Attacker uploaded a web shell (cache.php) to the upload directory and executed it, leading to a reverse shell.",
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ]
    },
    {
      "text": "The web shell established outbound network connection to an external IP 198.51.100.7 on port 4444.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    }
  ],
  "confidence": 0.95,
  "tool_trace": []
}
```

---
## SOC-012 - Kerberoasting followed by service-account reuse

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1558.003",
    "T1021.002"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "disable_account",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Service ticket enumeration indicates Kerberoasting",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Lateral movement via admin share using svc_sql account",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.8,
  "tool_trace": []
}
```

---
## SOC-011 - Signed updater during approved rollout

Task success: 0.556
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "benign",
  "incident_labels": [
    "execution"
  ],
  "attack_techniques": [
    "T1218"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "close_alert",
    "document_baseline"
  ],
  "claims": [
    {
      "text": "Authorized vendor update executed on pilot ring in approved change window.",
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.95,
  "tool_trace": []
}
```

---
## SOC-003 - PowerShell persistence after document execution

Task success: 0.756
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "execution",
    "persistence",
    "command_and_control"
  ],
  "attack_techniques": [
    "T1059.001",
    "T1547.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "preserve_evidence",
    "block_domain",
    "remove_persistence"
  ],
  "claims": [
    {
      "text": "Malicious PowerShell execution occurred via macro or exploit in Word.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Persistence installed via HKCU Run key.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Command-and-control communication to suspicious domain.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```

---
## SOC-005 - Reconstruct cross-host movement

Task success: 0.778
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_access",
    "lateral_movement"
  ],
  "attack_techniques": [
    "T1110",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "svc_backup account was brute-forced from 10.24.7.19.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon from same source indicates compromise.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "RDP session to FIN-WS22 shows lateral movement.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": []
}
```
