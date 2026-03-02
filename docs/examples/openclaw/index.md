# OpenClaw Case Study

A comprehensive threat model of the OpenClaw WebSocket localhost takeover vulnerability.

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Name** | OpenClaw WebSocket Localhost Takeover |
| **Severity** | Critical (CVSS 9.3) |
| **Fixed in** | v2026.2.25 |
| **Discovered by** | Oasis Security |

OpenClaw, a popular open-source AI agent, was vulnerable to hijacking from any website due to a chain of security flaws in how it handled localhost WebSocket connections.

## Attack Chain

| Step | Action | Vulnerability |
|------|--------|---------------|
| 1 | Victim visits malicious website | Social engineering |
| 2 | Website loads malicious JavaScript | - |
| 3 | JS opens WebSocket to localhost:9999 | WebSocket bypasses same-origin |
| 4 | JS brute-forces gateway password | No rate limiting |
| 5 | JS registers as trusted device | Auto-approve from localhost |
| 6-8 | Attacker controls AI agent | Full compromise |
| 9-10 | Data exfiltrated to attacker | Config, logs, API keys stolen |

## CVSS Vector

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.3 (Critical)
```

| Metric | Value | Explanation |
|--------|-------|-------------|
| AV:N | Network | Attack via website |
| AC:L | Low | Simple exploit |
| PR:N | None | No privileges needed |
| UI:R | Required | User visits page |
| S:C | Changed | Browser → Agent |
| C:H | High | Full data access |
| I:H | High | Full control |
| A:N | None | No availability impact |

## Framework Mappings

### STRIDE Analysis

| Category | Applies | Description |
|----------|---------|-------------|
| **Spoofing** | ✓ | Browser JS appears as localhost |
| **Tampering** | - | - |
| **Repudiation** | - | - |
| **Information Disclosure** | ✓ | API keys, configs exfiltrated |
| **Denial of Service** | - | - |
| **Elevation of Privilege** | ✓ | No rate limit + auto-approve |

### MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-by Compromise | T1189 |
| Initial Access | Trusted Relationship | T1199 |
| Credential Access | Brute Force | T1110 |
| Collection | Data from Local System | T1005 |
| Exfiltration | Over C2 Channel | T1041 |

### MITRE ATLAS

| Technique | ID | Description |
|-----------|-----|-------------|
| Prompt Injection | AML.T0024 | Control agent behavior |

### OWASP

| Category | ID | Name |
|----------|-----|------|
| API | API2:2023 | Broken Authentication |
| API | API4:2023 | Unrestricted Resource Consumption |
| LLM | LLM08:2023 | Excessive Agency |

### CWE

| ID | Name |
|----|------|
| CWE-346 | Origin Validation Error |
| CWE-307 | Improper Restriction of Excessive Auth Attempts |
| CWE-287 | Improper Authentication |

## Diagrams

### Data Flow Diagram

Shows system architecture and trust boundaries:

- Browser sandbox boundary
- Localhost implicit trust zone
- Data flows between components

```bash
tms generate dfd.json -o dfd.d2 --svg
```

### Attack Chain

Visualizes the 10-step attack sequence:

```bash
tms generate attack_chain.json -o attack_chain.d2 --svg
```

### Sequence Diagram

Time-ordered attack timeline:

```bash
tms generate attack_sequence.json -o attack_sequence.d2 --svg
```

## Key Security Lessons

!!! danger "Critical Findings"
    1. **Never exempt localhost from rate limiting** — browsers execute untrusted code
    2. **Require user confirmation for all device pairings** — even from loopback
    3. **Use cryptographic tokens over passwords** — for local service auth
    4. **Validate WebSocket Origin headers** — even for localhost
    5. **Consider Unix sockets** — instead of TCP localhost for local IPC

## Running the Demo

The repository includes a vulnerable demo server for educational purposes:

```bash
# Start vulnerable server
cd demo/vulnerable-server
go run main.go

# Open malicious page
cd demo/malicious-page
open index.html
```

!!! warning "Educational Only"
    The demo server is intentionally vulnerable. Do not use in production.

## JSON IR Example

```json
{
  "type": "attack-chain",
  "title": "OpenClaw WebSocket Localhost Takeover",
  "mappings": {
    "mitreAttack": [
      {"tacticId": "TA0001", "techniqueId": "T1189", "techniqueName": "Drive-by Compromise"},
      {"tacticId": "TA0006", "techniqueId": "T1110", "techniqueName": "Brute Force"}
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"}
    ],
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3
    }
  },
  "elements": [
    {"id": "attacker", "label": "Attacker", "type": "external-entity"},
    {"id": "browser", "label": "Victim Browser", "type": "browser"},
    {"id": "agent", "label": "AI Agent", "type": "agent", "classification": "crown-jewel"}
  ],
  "attacks": [
    {"step": 1, "from": "attacker", "to": "browser", "label": "Serve malicious page"},
    {"step": 2, "from": "browser", "to": "agent", "label": "WebSocket to localhost"}
  ]
}
```

## Files

| File | Description |
|------|-------------|
| `README.md` | Documentation |
| `dfd.json` | Data flow diagram IR |
| `attack_chain.json` | Attack chain IR |
| `attack_sequence.json` | Sequence diagram IR |
| `*.d2` | Generated D2 files |
| `*.svg` | Rendered diagrams |
| `article.html` | Full HTML article |
