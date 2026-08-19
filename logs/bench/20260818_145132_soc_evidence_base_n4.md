# CyberOrion SOC Evidence Benchmark

- Run: `20260818_145132_soc_evidence_base_n4`
- Arm: `bare` / mode `base`
- Model: `deepseek-v4-flash`
- Cases: 4
- Task Success: 0.756
- Evidence Grounding: 0.938
- ATT&CK F1: 0.875

## Failure Taxonomy

- unsupported_claim: 1

---
## SOC-002 - Authentication-to-RDP chain

Task success: 0.800
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "lateral_movement",
    "rdp_use"
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
    "isolate_fin_ws22",
    "disable_svc_backup_account",
    "block_source_ip_10_24_7_19",
    "review_rdp_access_logs"
  ],
  "claims": [
    {
      "text": "Brute force attack on svc_backup succeeded, leading to RDP session to FIN-WS22.",
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": [
    {
      "agent": "SOC_analyst",
      "tool": "auth_log_review",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "SOC_analyst",
      "tool": "edr_review",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-001 - Service-account password spray

Task success: 0.800
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "credential_brute_force",
    "lateral_movement",
    "rogue_rdp_access"
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
    "disable_svc_backup_account",
    "isolate_fin_ws22",
    "block_source_ip_10_24_7_19"
  ],
  "claims": [
    {
      "text": "Attacker brute-forced svc_backup account from 10.24.7.19 and succeeded.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Attacker then used the compromised account to establish RDP remote access to FIN-WS22.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.8,
  "tool_trace": [
    {
      "agent": "soc_analyst",
      "tool": "log_review",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-006 - Correlate identity and endpoint alerts

Task success: 0.800
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "lateral_movement",
    "rdp_compromise"
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
    "disable_svc_backup_account",
    "terminate_rdp_session_from_10.24.7.19",
    "reset_credentials_for_svc_backup"
  ],
  "claims": [
    {
      "text": "The account svc_backup was subject to a brute-force attack followed by a successful login from 10.24.7.19.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The compromised account was used for lateral movement via RDP to FIN-WS22.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": [
    {
      "agent": "defensive_soc_analyst",
      "tool": "event_correlation",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-003 - Contain a compromised service account

Task success: 0.625
Evidence Grounding: 0.750

### Agent / Tool Trace

- 01 `PlainLLM` analysis `-`

### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [
    "brute_force",
    "rdp_lateral_movement"
  ],
  "attack_techniques": [
    "T1110.001",
    "T1021.001"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3",
    "N1"
  ],
  "response_actions": [
    "isolate_fin_ws22",
    "reset_svc_backup_credentials",
    "review_rdp_policy"
  ],
  "claims": [
    {
      "text": "Failed logons indicate a brute-force attempt on svc_backup.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after failed attempts suggests password guessing succeeded.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "RDP session opened to FIN-WS22 indicates lateral movement.",
      "evidence_ids": [
        "E3"
      ]
    },
    {
      "text": "Scheduled inventory task completion may be benign but is included for completeness.",
      "evidence_ids": [
        "N1"
      ]
    }
  ],
  "confidence": 0.6,
  "tool_trace": [
    {
      "agent": "analyst",
      "tool": "manual_review",
      "status": "ok",
      "useful": true
    }
  ]
}
```
