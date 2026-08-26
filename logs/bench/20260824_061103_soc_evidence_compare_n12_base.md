# CyberOrion SOC Evidence Benchmark

- Run: `20260824_061103_soc_evidence_compare_n12_base`
- Arm: `bare` / mode `base`
- Model: `deepseek-v4-flash`
- Cases: 12
- Task Success: 0.867
- Evidence Grounding: 0.979
- ATT&CK F1: 0.358

## Failure Taxonomy

- attack_mapping: 7

---
## SOC-008 - Resist misleading benign records

Task success: 0.929
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
    "T1021"
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
      "text": "The svc_backup account was subject to a brute-force attack, as evidenced by 42 failed logons before a successful logon.",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "The compromise of svc_backup enabled lateral movement to FIN-WS22 via RDP, indicating unauthorized access.",
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
## SOC-006 - Legitimate backup activity with scanner noise

Task success: 0.714
Evidence Grounding: 1.000

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
    "E3"
  ],
  "response_actions": [
    "close_alert",
    "document_baseline"
  ],
  "claims": [
    {
      "text": "The backup service account login is authorized by change ticket CHG-8821.",
      "evidence_ids": [
        "E3"
      ]
    },
    {
      "text": "SMB share connections are consistent with the authorized backup and restore validation window.",
      "evidence_ids": [
        "E2",
        "E1"
      ]
    }
  ],
  "confidence": 0.95,
  "tool_trace": []
}
```

---
## SOC-001 - Service-account password spray

Task success: 0.952
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
      "text": "Brute-force attack on svc_backup account",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after brute force",
      "evidence_ids": [
        "E1",
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
## SOC-007 - Select reversible containment

Task success: 0.929
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
    "T1021"
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
      "text": "Multiple failed logons indicate a brute force attempt against svc_backup.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after brute force indicates account compromise.",
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
  "confidence": 0.9,
  "tool_trace": []
}
```

---
## SOC-002 - DNS tunnel with staged exfiltration

Task success: 0.857
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
    "T1048.003",
    "T1071.001",
    "T1560.001"
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
      "text": "Unusual DNS TXT queries with high-entropy subdomains indicate data exfiltration through DNS tunneling.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Large data transfer from ENG-17 via proxy exceeds normal baseline, consistent with exfiltration.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell compressed files before the DNS burst indicates preparation for exfiltration.",
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

Task success: 0.893
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
    "T1021"
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
      "text": "Brute-force attack on svc_backup, then successful logon.",
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
  "confidence": 0.85,
  "tool_trace": []
}
```

---
## SOC-009 - OAuth consent followed by mailbox collection

Task success: 0.829
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
    "T1550",
    "T1530",
    "T1098",
    "T1020"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "disable_account",
    "revoke_oauth_grants",
    "preserve_evidence",
    "block_domain"
  ],
  "claims": [
    {
      "text": "User approved an OAuth app named MailSync requesting Mail.Read scope, which is an unusual and risky permission.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "MailSync used the granted Mail.Read scope to read 1840 emails from a new ASN, indicating data exfiltration.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "A refresh token was used after a password reset, indicating persistence and possible token theft.",
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

Task success: 0.886
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
    "T1059",
    "T1071",
    "T1505.003"
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
      "text": "An attacker uploaded a PHP web shell to the uploads directory, executed it to run the id command, and established a reverse shell to an external IP.",
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
## SOC-012 - Kerberoasting followed by service-account reuse

Task success: 0.809
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
    "T1558",
    "T1021"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "disable_account"
  ],
  "claims": [
    {
      "text": "Workstation requested unusually high volume of service tickets, indicating password cracking or Kerberoasting.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Interactive logon with svc_sql from same workstation shows potential credential access.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "Connection to admin share suggests lateral movement using obtained credentials.",
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

Task success: 0.714
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
    "T1059"
  ],
  "evidence_ids": [
    "E1",
    "E3"
  ],
  "response_actions": [
    "close_alert",
    "document_baseline"
  ],
  "claims": [
    {
      "text": "Vendor updater executed msiexec as expected.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Binary hash matches vendor release, indicating legitimacy.",
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

Task success: 0.886
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
    "T1059",
    "T1547.001",
    "T1071"
  ],
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "response_actions": [
    "isolate_host",
    "remove_persistence",
    "block_domain",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Microsoft Word spawned a PowerShell process with an encoded command, indicating script execution.",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "A persistence mechanism was established via a new HKCU Run registry key pointing to a PowerShell payload.",
      "evidence_ids": [
        "E2"
      ]
    },
    {
      "text": "PowerShell communicated with a newly registered domain, indicating command-and-control activity.",
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
## SOC-005 - Reconstruct cross-host movement

Task success: 1.000
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
    "isolate_host",
    "disable_account",
    "preserve_evidence"
  ],
  "claims": [
    {
      "text": "Brute-force attack against svc_backup account from 10.24.7.19",
      "evidence_ids": [
        "E1"
      ]
    },
    {
      "text": "Successful logon after brute-force attempts indicates account compromise",
      "evidence_ids": [
        "E1",
        "E2"
      ]
    },
    {
      "text": "Lateral movement to FIN-WS22 via RDP after account compromise",
      "evidence_ids": [
        "E3"
      ]
    }
  ],
  "confidence": 0.85,
  "tool_trace": []
}
```
