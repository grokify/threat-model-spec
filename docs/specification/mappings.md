# Framework Mappings

The `mappings` field links threat models to industry security frameworks.

## Overview

```json
{
  "mappings": {
    "mitreAttack": [...],
    "mitreAtlas": [...],
    "owasp": [...],
    "stride": [...],
    "cwe": [...],
    "cvss": {...}
  }
}
```

## MITRE ATT&CK

```json
{
  "mitreAttack": [
    {
      "tacticId": "TA0001",
      "tacticName": "Initial Access",
      "techniqueId": "T1189",
      "techniqueName": "Drive-by Compromise",
      "description": "Malicious website exploits browser",
      "url": "https://attack.mitre.org/techniques/T1189"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tacticId` | string | Yes | Tactic ID (TA####) |
| `tacticName` | string | No | Tactic name |
| `techniqueId` | string | Yes | Technique ID (T####) |
| `techniqueName` | string | No | Technique name |
| `description` | string | No | Context |
| `url` | string | No | ATT&CK URL |

## MITRE ATLAS

```json
{
  "mitreAtlas": [
    {
      "tacticId": "AML.TA0002",
      "tacticName": "ML Artifact Collection",
      "techniqueId": "AML.T0024",
      "techniqueName": "Prompt Injection",
      "description": "Crafted prompts manipulate AI behavior"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tacticId` | string | Yes | Tactic ID (AML.TA####) |
| `tacticName` | string | No | Tactic name |
| `techniqueId` | string | Yes | Technique ID (AML.T####) |
| `techniqueName` | string | No | Technique name |
| `description` | string | No | Context |
| `url` | string | No | ATLAS URL |

## OWASP

```json
{
  "owasp": [
    {
      "category": "api",
      "id": "API2:2023",
      "name": "Broken Authentication",
      "description": "No rate limiting on authentication",
      "url": "https://owasp.org/API-Security/..."
    },
    {
      "category": "agentic",
      "id": "ASI02:2026",
      "name": "Tool Misuse & Exploitation",
      "description": "Attackers exploit agent's access to tools"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `category` | string | Yes | `web`, `api`, `llm`, or `agentic` |
| `id` | string | Yes | OWASP ID |
| `name` | string | Yes | Vulnerability name |
| `description` | string | No | Context |
| `url` | string | No | OWASP URL |

### OWASP Categories

| Category | Value | Year |
|----------|-------|------|
| Web Applications | `web` | 2021 |
| API Security | `api` | 2023 |
| LLM Applications | `llm` | 2025 |
| Agentic Applications | `agentic` | 2026 |

### Attack Step OWASP Mappings

Attack steps can include `owaspIds` and `asiIds`:

```json
{
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "agent",
      "label": "Inject malicious prompt",
      "owaspIds": ["LLM01:2025"],
      "asiIds": ["ASI01:2026", "ASI02:2026"]
    }
  ]
}
```

## STRIDE

```json
{
  "stride": [
    {
      "category": "S",
      "name": "Spoofing",
      "description": "Attacker impersonates legitimate client"
    },
    {
      "category": "I",
      "name": "Information Disclosure",
      "description": "API keys exposed to attacker"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `category` | string | Yes | S, T, R, I, D, or E |
| `name` | string | No | Category name |
| `description` | string | No | Context |

## CWE

```json
{
  "cwe": [
    {
      "id": "CWE-346",
      "name": "Origin Validation Error",
      "description": "WebSocket accepts any origin",
      "url": "https://cwe.mitre.org/data/definitions/346.html"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | CWE ID (CWE-###) |
| `name` | string | No | Weakness name |
| `description` | string | No | Context |
| `url` | string | No | CWE URL |

## CVSS

```json
{
  "cvss": {
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "score": 9.3,
    "severity": "Critical"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | CVSS version |
| `vector` | string | Yes | CVSS vector string |
| `score` | float | No | Calculated score |
| `severity` | string | No | Critical/High/Medium/Low |

## Complete Example

```json
{
  "type": "attack-chain",
  "title": "WebSocket Localhost Takeover",
  "mappings": {
    "mitreAttack": [
      {
        "tacticId": "TA0001",
        "tacticName": "Initial Access",
        "techniqueId": "T1189",
        "techniqueName": "Drive-by Compromise"
      },
      {
        "tacticId": "TA0006",
        "tacticName": "Credential Access",
        "techniqueId": "T1110",
        "techniqueName": "Brute Force"
      }
    ],
    "mitreAtlas": [
      {
        "techniqueId": "AML.T0024",
        "techniqueName": "Prompt Injection"
      }
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"},
      {"category": "api", "id": "API4:2023", "name": "Unrestricted Resource Consumption"},
      {"category": "llm", "id": "LLM06:2025", "name": "Excessive Agency"},
      {"category": "agentic", "id": "ASI02:2026", "name": "Tool Misuse & Exploitation"}
    ],
    "stride": [
      {"category": "S", "name": "Spoofing"},
      {"category": "I", "name": "Information Disclosure"},
      {"category": "E", "name": "Elevation of Privilege"}
    ],
    "cwe": [
      {"id": "CWE-346", "name": "Origin Validation Error"},
      {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts"}
    ],
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3,
      "severity": "Critical"
    }
  }
}
```

## STIX 2.1 Export

Framework mappings are preserved in STIX 2.1 export:

- **MITRE ATT&CK** → Attack Patterns with external references
- **MITRE ATLAS** → Attack Patterns with external references
- **CWE** → Vulnerability objects

```bash
tms generate model.json --stix -o model.stix.json
```
