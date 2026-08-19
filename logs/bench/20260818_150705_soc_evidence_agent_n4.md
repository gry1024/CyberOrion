# CyberOrion SOC Evidence Benchmark

- Run: `20260818_150705_soc_evidence_agent_n4`
- Arm: `framework` / mode `agent`
- Model: `deepseek-v4-flash`
- Cases: 4
- Task Success: 0.932
- Evidence Grounding: 0.938
- ATT&CK F1: 0.750

## Failure Taxonomy

- attack_mapping: 1

---
## SOC-002 - DNS tunnel with staged exfiltration

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
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "The DNS TXT queries to sync-cloud.example are abnormal in volume and entropy, indicating potential data exfiltration or C2.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "ENG-17 transferred 48 MB of data, exceeding baseline, consistent with data exfiltration after archiving.",
      "evidence_ids": [
        "E2",
        "E3"
      ]
    },
    {
      "text": "The PowerShell archive creation preceded the DNS burst, suggesting intentional data staging for exfiltration.",
      "evidence_ids": [
        "E3",
        "E1"
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
      "text": "Brute force attack on svc_backup account from 10.24.7.19, followed by successful logon and lateral movement to FIN-WS22 via RDP.",
      "evidence_ids": [
        "E1",
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
## SOC-006 - Legitimate backup activity with scanner noise

Task success: 0.750
Evidence Grounding: 0.750

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
  "verdict": "benign",
  "incident_labels": [
    "close_alert"
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
      "text": "The backup activity is authorized by change ticket and performed by the approved backup server during the maintenance window.",
      "evidence_ids": [
        "E3",
        "E1"
      ]
    }
  ],
  "confidence": 0.95,
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
## SOC-003 - PowerShell persistence after document execution

Task success: 0.978
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
      "text": "Malicious macro in a Word document launched PowerShell with an encoded command, indicating execution.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "A persistence mechanism was established via HKCU Run key pointing to the PowerShell payload.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "The PowerShell process communicated with a suspicious newly registered domain, indicating command and control.",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.92,
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
