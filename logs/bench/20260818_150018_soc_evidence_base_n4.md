# CyberOrion SOC Evidence Benchmark

- Run: `20260818_150018_soc_evidence_base_n4`
- Arm: `bare` / mode `base`
- Model: `deepseek-v4-flash`
- Cases: 4
- Task Success: 1.000
- Evidence Grounding: 1.000
- ATT&CK F1: 1.000

## Failure Taxonomy

- none

---
## SOC-002 - Authentication-to-RDP chain

Task success: 1.000
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
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "The service account svc_backup was subjected to a password spraying attack resulting in a successful logon, indicating credential compromise.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The compromised account was used to establish an RDP session to FIN-WS22, indicating lateral movement.",
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
## SOC-001 - Service-account password spray

Task success: 1.000
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
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Failed logons indicate a brute-force attempt against svc_backup.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after brute-force suggests credential access.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "RDP session initiated to FIN-WS22 indicates lateral movement.",
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
## SOC-006 - Correlate identity and endpoint alerts

Task success: 1.000
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
    "isolate_host",
    "disable_account",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Brute-force attack on svc_backup account from 10.24.7.19",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful authentication after brute force",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Lateral movement via RDP to FIN-WS22",
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
## SOC-003 - Contain a compromised service account

Task success: 1.000
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
    "isolate_host",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Likely brute-force attack on svc_backup leading to successful logon.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Lateral movement via RDP from svc_backup to FIN-WS22.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": []
}
```
