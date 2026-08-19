# CyberOrion SOC Evidence Benchmark

- Run: `20260818_150028_soc_evidence_agent_n4`
- Arm: `framework` / mode `agent`
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
      "text": "Adversary performed a brute force attack against svc_backup account, eventually gaining access.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Adversary used RDP for lateral movement to FIN-WS22.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "timeline.query",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack.lookup",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "playbook.search",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "evidence.verify",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-001 - Service-account password spray

Task success: 1.000
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
      "text": "svc_backup was targeted in a brute-force attack from 10.24.7.19",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "The attacker gained access via a successful logon using the same account and source IP",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Lateral movement to FIN-WS22 was facilitated via RDP",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "timeline.query",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack.lookup",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "playbook.search",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "evidence.verify",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-006 - Correlate identity and endpoint alerts

Task success: 1.000
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
      "text": "Brute force of svc_backup account succeeded from 10.24.7.19.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "After successful logon, the account initiated RDP to FIN-WS22, indicating lateral movement.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    }
  ],
  "confidence": 0.9,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "timeline.query",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack.lookup",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "playbook.search",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "evidence.verify",
      "status": "ok",
      "useful": true
    }
  ]
}
```

---
## SOC-003 - Contain a compromised service account

Task success: 1.000
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
      "text": "Multiple failed logons indicate a brute force attack.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after failures suggests compromised credentials.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "RDP session to another host indicates lateral movement.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": [
    {
      "agent": "TriageAgent",
      "tool": "timeline.query",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ThreatIntelAgent",
      "tool": "attack.lookup",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "ResponseAgent",
      "tool": "playbook.search",
      "status": "ok",
      "useful": true
    },
    {
      "agent": "CriticAgent",
      "tool": "evidence.verify",
      "status": "ok",
      "useful": true
    }
  ]
}
```
