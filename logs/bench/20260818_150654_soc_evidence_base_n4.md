# CyberOrion SOC Evidence Benchmark

- Run: `20260818_150654_soc_evidence_base_n4`
- Arm: `bare` / mode `base`
- Model: `deepseek-v4-flash`
- Cases: 4
- Task Success: 0.828
- Evidence Grounding: 0.938
- ATT&CK F1: 0.450

## Failure Taxonomy

- attack_mapping: 2
- unsupported_claim: 1

---
## SOC-002 - DNS tunnel with staged exfiltration

Task success: 0.857
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "command_and_control",
    "exfiltration"
  ],
  "attack_techniques": [
    "T1568",
    "T1041"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "preserve_evidence",
    "block_domain"
  ],
  "claims": [
    {
      "text": "The DNS TXT queries to sync-cloud.example were used to establish a covert C2 channel and exfiltrate data via high-entropy subdomains, as shown by the anomalous TXT query volume and payload size.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The host ENG-17 performed a large data transfer (48 MB) far exceeding its normal baseline, indicating exfiltration via the C2 channel.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell compressed archive design_docs.zip prior to the data transfer, preparing sensitive files for exfiltration.",
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
## SOC-001 - Service-account password spray

Task success: 0.952
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

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
      "text": "Attackers performed a brute-force attack against svc_backup account.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon from the same source IP indicates compromise of account.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "RDP session from the compromised account to another host indicates lateral movement.",
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

Task success: 0.559
Evidence Grounding: 0.750

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "benign",
  "incident_labels": [
    "benign_activity"
  ],
  "attack_techniques": [],
  "evidence_ids": [
    "E1",
    "E2",
    "E3",
    "N1"
  ],
  "response_actions": [
    "close_alert"
  ],
  "claims": [
    {
      "text": "Backup service account login from approved backup server matches authorized change ticket.",
      "evidence_ids": [
        "E1",
        "E3"
      ]
    },
    {
      "text": "SMB share access occurs during documented backup window and is consistent with backup operations.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    },
    {
      "text": "Low-confidence port scan from vulnerability scanner is likely scheduled scanning and not malicious.",
      "evidence_ids": [
        "N1"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```

---
## SOC-003 - PowerShell persistence after document execution

Task success: 0.943
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

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
    "preserve_evidence",
    "remove_persistence",
    "block_domain"
  ],
  "claims": [
    {
      "text": "Malicious macro or exploit in Word document launched PowerShell with encoded command",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "PowerShell established persistence via HKCU Run registry key",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell communicated with a newly registered suspicious domain",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```
