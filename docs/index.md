# Threat Model Spec

**Security threat modeling diagrams as code with D2 and STIX 2.1 export.**

Threat Model Spec is an open-source Go library and CLI for creating security threat modeling diagrams programmatically. Define your threat models in JSON, render them to D2 diagrams, and export to STIX 2.1 for threat intelligence sharing.

## Features

- **Design-Time Threat Modeling** — Proactive security analysis during SDLC with risk assessment
- **Risk Assessment** — Structured likelihood × impact scoring with categorical risk levels
- **Asset Inventory** — Sensitivity classification and compliance mapping
- **Scenario Modeling** — What-if attack scenarios with preconditions and attack paths
- **Diagrams-as-Code** — Define threat models in JSON, render to D2/SVG
- **Multiple Diagram Types** — DFD, Attack Chain, Sequence, Attack Tree diagrams
- **Threat Frameworks** — MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, STRIDE, LINDDUN, CWE, CVSS
- **Control Frameworks** — NIST CSF, CIS Controls v8, ISO 27001
- **Compliance Frameworks** — SOC 2, PCI-DSS, HIPAA, GDPR, FedRAMP
- **Security Lifecycle** — Mitigations, threat actors, detections, response actions
- **Network Topology** — Map elements to hosts, ports, protocols, and cloud infrastructure
- **STIX 2.1 Export** — Share threat intelligence in standard format
- **D2 Styles** — Color-coded STRIDE/LINDDUN annotations, trust boundaries, attack flows
- **Validation** — Type-specific field validation with strict mode
- **AI Agents** — Claude Code plugin for AI-assisted diagram creation

## Quick Example

Define a threat model in JSON using the `ThreatModel` format (the canonical multi-diagram representation):

```json
{
  "id": "websocket-localhost-takeover",
  "title": "WebSocket Localhost Takeover",
  "description": "Attack exploiting missing origin validation",
  "mappings": {
    "mitreAttack": [
      {"tacticId": "TA0001", "techniqueId": "T1189", "techniqueName": "Drive-by Compromise"}
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"}
    ]
  },
  "diagrams": [
    {
      "type": "attack-chain",
      "title": "Attack Chain",
      "elements": [
        {"id": "attacker", "label": "Attacker", "type": "external-entity"},
        {"id": "victim", "label": "Victim", "type": "process"}
      ],
      "attacks": [
        {"step": 1, "from": "attacker", "to": "victim", "label": "WebSocket to localhost"}
      ]
    }
  ]
}
```

Generate diagrams:

```bash
# Generate D2 diagram from ThreatModel
tms generate threat-model.json -o diagram.d2

# Also render to SVG
tms generate threat-model.json -o diagram.d2 --svg

# Export to STIX 2.1
tms generate threat-model.json --stix -o threat-model.stix.json
```

## Getting Started

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Installation**

    ---

    Install the Go library or CLI tool

    [:octicons-arrow-right-24: Install](getting-started/installation.md)

-   :material-rocket-launch:{ .lg .middle } **Quick Start**

    ---

    Create your first threat model diagram

    [:octicons-arrow-right-24: Quick Start](getting-started/quick-start.md)

-   :material-book-open-variant:{ .lg .middle } **Concepts**

    ---

    Learn about diagram types and security frameworks

    [:octicons-arrow-right-24: Concepts](concepts/diagram-types.md)

-   :material-code-json:{ .lg .middle } **Specification**

    ---

    JSON IR schema reference

    [:octicons-arrow-right-24: Specification](specification/index.md)

-   :material-robot:{ .lg .middle } **AI Agents**

    ---

    Claude Code plugin for AI-assisted diagram creation

    [:octicons-arrow-right-24: AI Agents](agents/index.md)

</div>

## Supported Frameworks

### Threat Frameworks

| Framework | Description |
|-----------|-------------|
| [STRIDE](concepts/frameworks/stride.md) | Microsoft threat categorization model |
| [LINDDUN](concepts/frameworks/linddun.md) | Privacy threat framework |
| [MITRE ATT&CK](concepts/frameworks/mitre-attack.md) | Adversary tactics and techniques |
| [MITRE ATLAS](concepts/frameworks/mitre-atlas.md) | AI/ML threat matrix |
| [OWASP Top 10](concepts/frameworks/owasp.md) | Web, API, and LLM security risks |
| [CWE](concepts/frameworks/cwe.md) | Common Weakness Enumeration |
| [CVSS](concepts/frameworks/cvss.md) | Common Vulnerability Scoring System |

### Control & Compliance Frameworks

| Framework | Description |
|-----------|-------------|
| NIST CSF | Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover) |
| CIS Controls v8 | Critical Security Controls with implementation groups |
| ISO 27001 | Information security management |
| SOC 2, PCI-DSS, HIPAA, GDPR | Compliance framework references |

## License

MIT License - see [LICENSE](https://github.com/grokify/threat-model-spec/blob/main/LICENSE)
