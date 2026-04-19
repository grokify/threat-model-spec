# Threat Model Spec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/grokify/threat-model-spec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/grokify/threat-model-spec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/grokify/threat-model-spec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/grokify/threat-model-spec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/grokify/threat-model-spec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/grokify/threat-model-spec/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/threat-model-spec
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/threat-model-spec
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/threat-model-spec
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/threat-model-spec
 [viz-svg]: https://img.shields.io/badge/visualizaton-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fthreat-model-spec
 [loc-svg]: https://tokei.rs/b1/github/grokify/threat-model-spec
 [repo-url]: https://github.com/grokify/threat-model-spec
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/threat-model-spec/blob/master/LICENSE

Threat Model Spec is an open-source library for creating security threat modeling diagrams as code. It provides a JSON-based intermediate representation (IR) that can be rendered to D2 diagrams and STIX 2.1 for threat intelligence sharing.

## Architecture

```
                         ┌──────────────────────┐
                         │     ThreatModel      │
                         │  (Canonical Source)  │
                         └──────────┬───────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       │              │             │             │              │
       ▼              ▼             ▼             ▼              ▼
  ┌─────────┐   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │   DFD   │   │  Attack  │  │ Sequence │  │  Attack  │  │ Security │
  │ Diagram │   │  Chain   │  │ Diagram  │  │   Tree   │  │ Metadata │
  └────┬────┘   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │             │             │             │             │
       └─────────────┴─────────────┴─────────────┴─────────────┘
                                   │
                   ┌───────────────┼──────────────┐
                   │               │              │
                   ▼               ▼              ▼
              ┌──────────┐   ┌──────────┐   ┌──────────┐
              │    D2    │   │   STIX   │   │ Validate │
              │ Renderer │   │ Exporter │   │          │
              └────┬─────┘   └─────┬────┘   └─────┬────┘
                   │               │              │
                   ▼               ▼              ▼
              ┌──────────┐   ┌──────────┐   ┌──────────┐
              │   .d2    │   │  .json   │   │  pass/   │
              │  → .svg  │   │  STIX    │   │  fail    │
              └──────────┘   │  Bundle  │   └──────────┘
                             └──────────┘
```

**Input:** ThreatModel JSON with shared metadata, framework mappings, and multiple diagram views

**Outputs:**

- **D2 Diagrams** → SVG/PNG via D2 CLI (one per diagram view)
- **STIX 2.1 Bundles** → Threat intelligence sharing
- **Validation Results** → Schema and reference checking

## Features

- **Diagrams-as-Code** — Define threat models in JSON, render to D2/SVG
- **Multiple Diagram Types** — DFD, Attack Chain, Sequence, Attack Tree diagrams
- **Framework Mappings** — MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, STRIDE, LINDDUN, CWE, CVSS, CVE
- **Control Frameworks** — NIST CSF, CIS Controls v8, ISO 27001 mappings
- **Compliance Frameworks** — SOC 2, PCI-DSS, HIPAA, GDPR, FedRAMP, and more
- **Mitigations** — Track countermeasures with status (implemented, planned, accepted)
- **Threat Actors** — Document adversary profiles with sophistication and motivation
- **Detection & Response** — Define detection capabilities and response actions
- **STIX 2.1 Export** — Share threat intelligence in standard format
- **D2 Styles** — Color-coded STRIDE/LINDDUN annotations, trust boundaries, attack flows
- **Validation** — Type-specific field validation with strict mode
- **AI Agents** — Claude Code plugin for AI-assisted diagram creation

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

A ThreatModel is the canonical format containing shared metadata and multiple diagram views:

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

Single-diagram files (DiagramIR format) are also supported for simpler use cases.

### Generate Diagrams

```bash
# Generate D2 diagram from ThreatModel
tms generate threat-model.json -o diagram.d2

# Also render to SVG
tms generate threat-model.json -o diagram.d2 --svg

# Export to STIX 2.1
tms generate threat-model.json --stix -o threat-model.stix.json

# Validate only
tms validate threat-model.json
```

## Diagram Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `dfd` | Data Flow Diagram | elements, boundaries, flows |
| `attack-chain` | Attack sequence | elements, attacks, targets |
| `sequence` | Time-ordered messages | actors, messages, phases |
| `attack-tree` | Hierarchical attack decomposition | attackTree (nodes with AND/OR logic) |

## Framework Mappings

### Threat Frameworks

| Framework | Field | Example |
|-----------|-------|---------|
| MITRE ATT&CK | `mitreAttack` | `{"tacticId": "TA0001", "techniqueId": "T1189"}` |
| MITRE ATLAS | `mitreAtlas` | `{"tacticId": "AML.TA0002", "techniqueId": "AML.T0024"}` |
| OWASP | `owasp` | `{"category": "api", "id": "API2:2023"}` |
| STRIDE | `stride` | `{"category": "S", "name": "Spoofing"}` |
| LINDDUN | `linddun` | `{"category": "I", "name": "Identifiability"}` |
| CWE | `cwe` | `{"id": "CWE-346", "name": "Origin Validation Error"}` |
| CVE | `cve` | `{"id": "CVE-2024-12345"}` |
| CVSS | `cvss` | `{"version": "3.1", "vector": "CVSS:3.1/..."}` |

### Control Frameworks

| Framework | Field | Example |
|-----------|-------|---------|
| NIST CSF | `controls.nistCsf` | `{"function": "Protect", "category": "PR.AC"}` |
| CIS Controls | `controls.cis` | `{"controlId": "16", "safeguardId": "16.4"}` |
| ISO 27001 | `controls.iso27001` | `{"controlId": "A.9.2.3"}` |

### Compliance Frameworks

| Framework | Value | Description |
|-----------|-------|-------------|
| SOC 2 | `soc2` | AICPA Service Organization Controls |
| PCI-DSS | `pci-dss` | Payment Card Industry Data Security |
| HIPAA | `hipaa` | Health Insurance Portability |
| GDPR | `gdpr` | General Data Protection Regulation |
| FedRAMP | `fedramp` | Federal Risk Authorization |
| NIST SP 800-53 | `nist-sp-800-53` | Security Controls Catalog |

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

### LINDDUN Privacy Threats

| Category | Color | Description |
|----------|-------|-------------|
| L - Linkability | Indigo | Linking items of interest |
| I - Identifiability | Blue | Identifying data subjects |
| N - Non-repudiation | Orange | Unable to deny actions |
| D - Detectability | Pink | Detecting item existence |
| Di - Disclosure | Red | Information disclosure |
| U - Unawareness | Purple | Lack of awareness |
| Nc - Non-compliance | Brown | Regulatory non-compliance |

### Trust Boundaries

| Type | Color | Use For |
|------|-------|---------|
| `browser` | Blue | Browser sandbox |
| `localhost` | Purple | Localhost implicit trust |
| `network` | Green | Network zones |
| `breached` | Dark red | Compromised boundaries |

### Mitigation Status

| Status | Color | Description |
|--------|-------|-------------|
| `implemented` | Green | Fully implemented |
| `partial` | Orange | Partially implemented |
| `planned` | Blue | Planned for future |
| `accepted` | Gray | Risk accepted |
| `transferred` | Light blue | Risk transferred |

## Security Lifecycle

### Mitigations

Track countermeasures for identified threats:

```json
{
  "mitigations": [
    {
      "id": "mit-1",
      "title": "Implement Origin Validation",
      "status": "implemented",
      "threatIds": ["threat-1"],
      "owner": "security-team"
    }
  ]
}
```

### Threat Actors

Document adversary profiles:

```json
{
  "threatActors": [
    {
      "id": "actor-1",
      "name": "External Attacker",
      "type": "criminal",
      "sophistication": "medium",
      "motivations": ["financial"]
    }
  ]
}
```

### Detection & Response

Define detection capabilities:

```json
{
  "detections": [
    {
      "id": "det-1",
      "title": "WebSocket Origin Anomaly",
      "coverage": "full",
      "dataSources": ["logs", "waf"]
    }
  ]
}
```

## AI Agents

The `agents/` directory contains specifications for AI-assisted threat model diagram creation:

| Agent | Description |
|-------|-------------|
| `dfd-creator` | Creates Data Flow Diagrams with numbered flows and trust boundaries |
| `attack-flow-visualizer` | Creates attack chain diagrams with MITRE ATT&CK annotations |
| `diagram-quality-reviewer` | Reviews diagrams for layout quality and legend clarity |

### Claude Code Plugin

Install the Claude Code plugin for AI-assisted diagram creation:

```bash
claude plugins add ./agents/plugins/claude
```

Use the `/create-dfd` command to generate diagrams interactively.

## Specification

The Threat Model Specification follows a versioned schema approach similar to OpenAPI.

| Version | Schema | Specification |
|---------|--------|---------------|
| v0.4.0 | [threat-model.schema.json](docs/versions/v0.4.0/threat-model.schema.json) | [specification.md](docs/versions/v0.4.0/specification.md) |

### Schema URLs

```
https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/threat-model.schema.json
https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/diagram.schema.json
```

### Using the Schema

Reference the schema in your threat model JSON:

```json
{
  "$schema": "https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/threat-model.schema.json",
  "id": "my-threat-model",
  "title": "My Application Threat Model",
  "diagrams": [...]
}
```

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
