# CyberOrion SOC Evidence Benchmark

- Run: `20260818_145142_soc_evidence_agent_n4`
- Arm: `framework` / mode `agent`
- Model: `deepseek-v4-flash`
- Cases: 4
- Task Success: 0.785
- Evidence Grounding: 1.000
- ATT&CK F1: 1.000

## Failure Taxonomy

- none

---
## SOC-002 - Authentication-to-RDP chain

Task success: 0.842
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `Commander` agent_dispatch `TriageAgent`
- 02 `TriageAgent` tool_call `timeline.query`
- 03 `Commander` agent_dispatch `ThreatIntelAgent`
- 04 `ThreatIntelAgent` tool_call `attack.lookup`
- 05 `Commander` agent_dispatch `ResponseAgent`
- 06 `ResponseAgent` tool_call `playbook.search`
- 07 `CriticAgent` evidence_check `evidence.verify`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "account_compromise",
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
    "disable_svc_backup_account",
    "isolate_fin_ws22",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Attacker performed brute force and successfully logged in as svc_backup.",
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
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "correlation",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack_mapping",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "playbook",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "claim_validation",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-001 - Service-account password spray

Task success: 0.750
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `Commander` agent_dispatch `TriageAgent`
- 02 `TriageAgent` tool_call `timeline.query`
- 03 `Commander` agent_dispatch `ThreatIntelAgent`
- 04 `ThreatIntelAgent` tool_call `attack.lookup`
- 05 `Commander` agent_dispatch `ResponseAgent`
- 06 `ResponseAgent` tool_call `playbook.search`
- 07 `CriticAgent` evidence_check `evidence.verify`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "rdp_abuse"
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
    "disable_account_svc_backup",
    "isolate_fin_ws22",
    "block_source_ip_10_24_7_19"
  ],
  "claims": [
    {
      "text": "Attacker performed brute force against svc_backup to gain access from 10.24.7.19.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Attacker used RDP to move laterally to FIN-WS22 using svc_backup.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "correlation",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack_mapping",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "containment",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "claim_validation",
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

- 01 `Commander` agent_dispatch `TriageAgent`
- 02 `TriageAgent` tool_call `timeline.query`
- 03 `Commander` agent_dispatch `ThreatIntelAgent`
- 04 `ThreatIntelAgent` tool_call `attack.lookup`
- 05 `Commander` agent_dispatch `ResponseAgent`
- 06 `ResponseAgent` tool_call `playbook.search`
- 07 `CriticAgent` evidence_check `evidence.verify`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
    "lateral_movement",
    "rdp_abuse"
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
    "disable_account_svc_backup",
    "isolate_fin-ws22",
    "preserve_evidence_logs"
  ],
  "claims": [
    {
      "text": "The account svc_backup was subject to a brute force attack, likely password spraying, from 10.24.7.19.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The attacker successfully authenticated as svc_backup from the same source IP.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "The attacker used the compromised account to establish an RDP session to FIN-WS22, indicating lateral movement.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "CorrelationEngine",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "ATT&CKMapper",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "PlaybookExecutor",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "ClaimValidator",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-003 - Contain a compromised service account

Task success: 0.750
Evidence Grounding: 1.000

### Agent / Tool Trace

- 01 `Commander` agent_dispatch `TriageAgent`
- 02 `TriageAgent` tool_call `timeline.query`
- 03 `Commander` agent_dispatch `ThreatIntelAgent`
- 04 `ThreatIntelAgent` tool_call `attack.lookup`
- 05 `Commander` agent_dispatch `ResponseAgent`
- 06 `ResponseAgent` tool_call `playbook.search`
- 07 `CriticAgent` evidence_check `evidence.verify`

### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [
    "brute_force",
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
    "disable_account_svc_backup",
    "isolate_fin_ws22"
  ],
  "claims": [
    {
      "text": "svc_backup was subject to a brute force attack, as indicated by 42 failed logons followed by a successful logon.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The attacker used the compromised svc_backup account to establish an RDP session to FIN-WS22.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "correlation",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack_mapping",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "containment",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "claim_validation",
      "status": "ok",
      "useful": true
    }
  ]
}
```
