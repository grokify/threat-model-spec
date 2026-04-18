# Threat Model Spec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

Threat Model Spec is an open-source library for creating security threat modeling diagrams as code. It provides a JSON-based intermediate representation (IR) that can be rendered to D2 diagrams and STIX 2.1 for threat intelligence sharing.

## Architecture

```
                         ┌──────────────────────┐
                         │     ThreatModel      │
                         │  (Canonical Source)  │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       ┌────────────┐        ┌────────────┐        ┌────────────┐
       │    DFD     │        │  Attack    │        │  Sequence  │
       │  Diagram   │        │   Chain    │        │  Diagram   │
       └─────┬──────┘        └─────┬──────┘        └─────┬──────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
             ┌──────────┐   ┌──────────┐   ┌──────────┐
             │    D2    │   │   STIX   │   │ Validate │
             │ Renderer │   │ Exporter │   │          │
             └────┬─────┘   └────┬─────┘   └────┬─────┘
                  │              │              │
                  ▼              ▼              ▼
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

- 💻 **Diagrams-as-Code** — Define threat models in JSON, render to D2/SVG
- 📊 **Multiple Diagram Types** — DFD, Attack Chain, Sequence diagrams
- 🗺️ **Framework Mappings** — MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, STRIDE, CWE, CVSS
- 📤 **STIX 2.1 Export** — Share threat intelligence in standard format
- 🎨 **D2 Styles** — Color-coded STRIDE annotations, trust boundaries, attack flows
- ✅ **Validation** — Type-specific field validation
- 🤖 **AI Agents** — Claude Code plugin for AI-assisted diagram creation

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
