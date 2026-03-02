# Threat Model Spec

**Security threat modeling diagrams as code with D2 and STIX 2.1 export.**

Threat Model Spec is an open-source Go library and CLI for creating security threat modeling diagrams programmatically. Define your threat models in JSON, render them to D2 diagrams, and export to STIX 2.1 for threat intelligence sharing.

## Features

- 💻 **Diagrams-as-Code** — Define threat models in JSON, render to D2/SVG
- 📊 **Multiple Diagram Types** — DFD, Attack Chain, Sequence diagrams
- 🗺️ **Framework Mappings** — MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, STRIDE, CWE, CVSS
- 📤 **STIX 2.1 Export** — Share threat intelligence in standard format
- 🎨 **D2 Styles** — Color-coded STRIDE annotations, trust boundaries, attack flows
- ✅ **Validation** — Type-specific field validation

## Quick Example

Define a threat model in JSON:

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

Generate diagrams:

```bash
# Generate D2 diagram
tms generate attack.json -o attack.d2

# Also render to SVG
tms generate attack.json -o attack.d2 --svg

# Export to STIX 2.1
tms generate attack.json --stix -o attack.stix.json
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

</div>

## Supported Frameworks

| Framework | Description |
|-----------|-------------|
| [STRIDE](concepts/frameworks/stride.md) | Microsoft threat categorization model |
| [MITRE ATT&CK](concepts/frameworks/mitre-attack.md) | Adversary tactics and techniques |
| [MITRE ATLAS](concepts/frameworks/mitre-atlas.md) | AI/ML threat matrix |
| [OWASP Top 10](concepts/frameworks/owasp.md) | Web, API, and LLM security risks |
| [CWE](concepts/frameworks/cwe.md) | Common Weakness Enumeration |
| [CVSS](concepts/frameworks/cvss.md) | Common Vulnerability Scoring System |

## Example: OpenClaw Vulnerability

See the complete [OpenClaw case study](examples/openclaw/index.md) demonstrating a WebSocket localhost takeover vulnerability with:

- Data Flow Diagram (DFD)
- Attack Chain with MITRE ATT&CK mapping
- Sequence Diagram
- STRIDE threat analysis

## License

MIT License - see [LICENSE](https://github.com/grokify/threat-model-spec/blob/main/LICENSE)
