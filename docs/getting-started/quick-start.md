# Quick Start

This guide walks you through creating your first threat model diagram.

## 1. Define a Threat Model

Create a JSON file describing your threat model. Here's a simple attack chain example:

```json title="attack.json"
{
  "type": "attack-chain",
  "title": "WebSocket Localhost Takeover",
  "description": "Malicious website exploits localhost WebSocket to compromise AI agent",
  "mappings": {
    "mitreAttack": [
      {
        "tacticId": "TA0001",
        "tacticName": "Initial Access",
        "techniqueId": "T1189",
        "techniqueName": "Drive-by Compromise"
      }
    ],
    "owasp": [
      {
        "category": "api",
        "id": "API2:2023",
        "name": "Broken Authentication"
      }
    ]
  },
  "elements": [
    {"id": "attacker", "label": "Attacker", "type": "external-entity"},
    {"id": "browser", "label": "Victim Browser", "type": "browser"},
    {"id": "agent", "label": "AI Agent", "type": "agent"}
  ],
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "browser",
      "label": "Serve malicious page",
      "mitreTechnique": "T1189"
    },
    {
      "step": 2,
      "from": "browser",
      "to": "agent",
      "label": "WebSocket to localhost:9999",
      "mitreTechnique": "T1557"
    }
  ],
  "targets": [
    {
      "elementId": "agent",
      "impact": "Full agent compromise, data exfiltration"
    }
  ]
}
```

## 2. Generate D2 Diagram

Use the `tms` CLI to generate a D2 diagram:

```bash
tms generate attack.json -o attack.d2
```

This creates a D2 file that can be rendered with the D2 CLI.

## 3. Render to SVG

Add the `--svg` flag to also render the diagram to SVG:

```bash
tms generate attack.json -o attack.d2 --svg
```

This creates both `attack.d2` and `attack.svg`.

## 4. Validate Your Model

Validate a threat model JSON file:

```bash
tms validate attack.json
# Output: Validation passed: attack.json
```

Use strict validation for additional checks:

```bash
tms validate attack.json --strict
```

## 5. Export to STIX 2.1

Export your threat model to STIX 2.1 format for sharing:

```bash
tms generate attack.json --stix -o attack.stix.json
```

## Diagram Types

Threat Model Spec supports three diagram types:

| Type | Use Case | Key Fields |
|------|----------|------------|
| `dfd` | Data Flow Diagrams | elements, boundaries, flows |
| `attack-chain` | Attack sequences | elements, attacks, targets |
| `sequence` | Time-ordered messages | actors, messages, phases |

### Data Flow Diagram (DFD)

```json
{
  "type": "dfd",
  "title": "System Architecture",
  "elements": [
    {"id": "user", "label": "User", "type": "external-entity"},
    {"id": "web", "label": "Web Server", "type": "process"},
    {"id": "db", "label": "Database", "type": "datastore"}
  ],
  "boundaries": [
    {"id": "dmz", "label": "DMZ", "type": "network", "elements": ["web"]}
  ],
  "flows": [
    {"from": "user", "to": "web", "label": "HTTPS Request"},
    {"from": "web", "to": "db", "label": "SQL Query"}
  ]
}
```

### Sequence Diagram

```json
{
  "type": "sequence",
  "title": "Attack Sequence",
  "actors": [
    {"id": "attacker", "label": "Attacker", "malicious": true},
    {"id": "victim", "label": "Victim"}
  ],
  "messages": [
    {"from": "attacker", "to": "victim", "label": "Phishing email", "type": "attack"},
    {"from": "victim", "to": "attacker", "label": "Credentials", "type": "exfil"}
  ]
}
```

## Next Steps

- [Diagram Types](../concepts/diagram-types.md) — Detailed diagram type reference
- [Security Frameworks](../concepts/frameworks/index.md) — STRIDE, MITRE ATT&CK, OWASP mappings
- [D2 Styles](../styles/index.md) — Color-coded threat annotations
- [OpenClaw Example](../examples/openclaw/index.md) — Complete case study
