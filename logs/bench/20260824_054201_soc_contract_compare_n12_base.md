# CyberOrion SOC Evidence Benchmark

- Run: `20260824_054201_soc_contract_compare_n12_base`
- Arm: `bare` / mode `base`
- Model: `deepseek-v4-flash`
- Cases: 12
- Task Success: 0.309
- Evidence Grounding: 0.000
- ATT&CK F1: 0.000

## Failure Taxonomy

- attack_mapping: 12
- missing_evidence: 12

---
## SOC-008 - Resist misleading benign records

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "attacker_compromised_privileged_account",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-006 - Legitimate backup activity with scanner noise

Task success: 0.429
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "benign",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-001 - Service-account password spray

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-007 - Select reversible containment

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [
    "T1110.001 (Brute Force: Password Guessing)",
    "T1021.001 (Remote Services: Remote Desktop Protocol)",
    "T1078 (Valid Accounts)"
  ],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-002 - DNS tunnel with staged exfiltration

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-004 - Find the signal in maintenance noise

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-009 - OAuth consent followed by mailbox collection

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-010 - Linux webshell and outbound reverse shell

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-012 - Kerberoasting followed by service-account reuse

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-011 - Signed updater during approved rollout

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-003 - PowerShell persistence after document execution

Task success: 0.286
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "unknown",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```

---
## SOC-005 - Reconstruct cross-host movement

Task success: 0.429
Evidence Grounding: 0.000

### Agent / Tool Trace


### Prediction

```json
{
  "verdict": "malicious",
  "incident_labels": [],
  "attack_techniques": [],
  "evidence_ids": [],
  "response_actions": [],
  "claims": [],
  "confidence": 0.0,
  "tool_trace": []
}
```
