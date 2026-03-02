# Threat Model Spec

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Threat Model Spec is an open-source library for creating security threat modeling diagrams as code. It provides a JSON-based intermediate representation (IR) that can be rendered to D2 diagrams and STIX 2.1 for threat intelligence sharing.

## Features

- **Diagrams-as-Code** — Define threat models in JSON, render to D2/SVG
- **Multiple Diagram Types** — DFD, Attack Chain, Sequence diagrams
- **Framework Mappings** — MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, STRIDE, CWE, CVSS
- **STIX 2.1 Export** — Share threat intelligence in standard format
- **D2 Styles** — Color-coded STRIDE annotations, trust boundaries, attack flows
- **Validation** — Type-specific field validation

## Installation

### Go Library

```bash
go get github.com/grokify/threat-model-spec
```

### CLI Tool

```bash
go install github.com/grokify/threat-model-spec/cmd/tms@latest
```

## Quick Start

### Define a Threat Model (JSON)

```json
{
  "type": "attack-chain",
  "title": "WebSocket Localhost Takeover",
  "mappings": {
    "mitreAttack": [
      {"tacticId": "TA0001", "techniqueId": "T1189", "techniqueName": "Drive-by Compromise"}
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"}
    ]
  },
  "elements": [
    {"id": "attacker", "label": "Attacker", "type": "external-entity"},
    {"id": "victim", "label": "Victim", "type": "process"}
  ],
  "attacks": [
    {"step": 1, "from": "attacker", "to": "victim", "label": "WebSocket to localhost"}
  ]
}
```

### Generate Diagrams

```bash
# Generate D2 diagram
tms generate attack.json -o attack.d2

# Also render to SVG
tms generate attack.json -o attack.d2 -svg

# Export to STIX 2.1
tms generate attack.json --stix -o attack.stix.json

# Validate only
tms validate attack.json
```

## Diagram Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `dfd` | Data Flow Diagram | elements, boundaries, flows |
| `attack-chain` | Attack sequence | elements, attacks, targets |
| `sequence` | Time-ordered messages | actors, messages, phases |

## Framework Mappings

| Framework | Field | Example |
|-----------|-------|---------|
| MITRE ATT&CK | `mitreAttack` | `{"tacticId": "TA0001", "techniqueId": "T1189"}` |
| MITRE ATLAS | `mitreAtlas` | `{"tacticId": "AML.TA0002", "techniqueId": "AML.T0024"}` |
| OWASP | `owasp` | `{"category": "api", "id": "API2:2023"}` |
| STRIDE | `stride` | `{"category": "S", "name": "Spoofing"}` |
| CWE | `cwe` | `{"id": "CWE-346", "name": "Origin Validation Error"}` |
| CVSS | `cvss` | `{"version": "3.1", "vector": "CVSS:3.1/..."}` |

## D2 Style Reference

### STRIDE Threat Annotations

| Category | Color | Description |
|----------|-------|-------------|
| S - Spoofing | Red | Identity spoofing |
| T - Tampering | Yellow | Data tampering |
| R - Repudiation | Purple | Non-repudiation failures |
| I - Information Disclosure | Blue | Information leakage |
| D - Denial of Service | Orange | Availability attacks |
| E - Elevation of Privilege | Green | Privilege escalation |

### Trust Boundaries

| Type | Color | Use For |
|------|-------|---------|
| `browser` | Blue | Browser sandbox |
| `localhost` | Purple | Localhost implicit trust |
| `network` | Green | Network zones |
| `breached` | Dark red | Compromised boundaries |

## Examples

See [examples/openclaw/](examples/openclaw/) for a complete threat model of the OpenClaw WebSocket vulnerability, including:

- Data Flow Diagram (DFD)
- Attack Chain with MITRE ATT&CK mapping
- Attack Sequence diagram
- HTML article with all diagrams

## Requirements

- Go 1.24+
- [D2](https://d2lang.com) v0.6+ for SVG rendering

## License

MIT License - see [LICENSE](LICENSE)

## References

- [D2 Language](https://d2lang.com)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html)
