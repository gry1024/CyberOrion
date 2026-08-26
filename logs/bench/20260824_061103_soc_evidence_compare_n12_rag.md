# CyberOrion SOC Evidence Benchmark

- Run: `20260824_061103_soc_evidence_compare_n12_rag`
- Arm: `rag` / mode `rag`
- Model: `deepseek-v4-flash`
- Cases: 12
- Task Success: 0.727
- Evidence Grounding: 0.979
- ATT&CK F1: 0.800

## Failure Taxonomy

- attack_mapping: 2

---
## SOC-008 - Resist misleading benign records

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
      "text": "Brute force attack on svc_backup account succeeded from 10.24.7.19",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Lateral movement to FIN-WS22 via RDP using svc_backup",
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

Task success: 0.556
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "benign",
  "incident_labels": [
    "legitimate_activity"
  ],
  "attack_techniques": [],
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
      "text": "The backup service account logged in from an approved backup server during the expected maintenance window.",
      "evidence_ids": [
        "E1",
        "E3"
      ]
    },
    {
      "text": "The SMB connections from BAK-01 to documented shares align with the authorized backup operations.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
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
      "text": "The account svc_backup was subject to a brute force attack that succeeded, enabling lateral movement via RDP.",
      "evidence_ids": [
        "E1",
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
## SOC-007 - Select reversible containment

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
      "text": "Failed logons followed by a successful logon from the same source indicate a successful brute force attack.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The RDP session to FIN-WS22 indicates lateral movement using remote services.",
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
## SOC-002 - DNS tunnel with staged exfiltration

Task success: 0.733
Evidence Grounding: 1.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "command_and_control",
    "exfiltration",
    "execution"
  ],
  "attack_techniques": [
    "T1071.004",
    "T1048",
    "T1059.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "block_domain",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "DNS queries to sync-cloud.example are anomalous and indicate tunneling activity.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Host ENG-17 transmitted 48MB over DNS, far exceeding baseline, indicating exfiltration.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell created a compressed archive just before the DNS burst, suggesting data staging for exfiltration.",
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
## SOC-004 - Find the signal in maintenance noise

Task success: 0.750
Evidence Grounding: 0.750

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
    "E3",
    "N1"
  ],
  "response_actions": [
    "disable_account",
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "A brute force attack was performed against svc_backup from 10.24.7.19, evidenced by 42 failed logons.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The attacker succeeded in logging in as svc_backup from the same IP.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Using the compromised account, the attacker moved laterally to FIN-WS22 via RDP.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.95,
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
      "text": "User approved an unverified OAuth app with Mail.Read scope, indicating a potential token theft or consent grant attack.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The app exfiltrated a large volume of emails via Graph API from a new ASN, indicating data theft.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "A refresh token was used after password reset, indicating persistent access via token.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.93,
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
    "persistence",
    "command_and_control"
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
    "remove_persistence",
    "block_domain"
  ],
  "claims": [
    {
      "text": "A web shell was uploaded to the upload directory and executed, allowing command execution.",
      "evidence_ids": [
        "E3",
        "E1"
      ]
    },
    {
      "text": "The web shell spawned a reverse shell to an external IP, indicating command and control.",
      "evidence_ids": [
        "E2"
      ]
    }
  ],
  "confidence": 0.9,
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
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "disable_account",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Service ticket requests indicate Kerberoasting activity.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Service account used to access admin share indicates lateral movement.",
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
    "T1218",
    "T1072"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "document_baseline",
    "close_alert"
  ],
  "claims": [
    {
      "text": "The msiexec process was spawned by a signed vendor updater as part of an authorized maintenance activity.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The binary hash matches the vendor release manifest, confirming authenticity of the update package.",
      "evidence_ids": [
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

Task success: 0.733
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
    "T1547.001",
    "T1071.001"
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
    "remove_persistence"
  ],
  "claims": [
    {
      "text": "Microsoft Word spawned PowerShell with an encoded command, indicating code execution.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "A new Registry Run key was created to establish persistence.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell communicated with a newly registered domain, indicating C2.",
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
      "text": "svc_backup account experienced a brute force attack from 10.24.7.19",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The brute force succeeded, leading to a successful logon",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "The compromised account was used for lateral movement via RDP",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```
