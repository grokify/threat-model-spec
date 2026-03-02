# JSON IR Specification

Threat Model Spec uses a JSON-based Intermediate Representation (IR) for defining threat models. This non-polymorphic structure is designed to be Go-friendly and generate clean JSON schemas.

## Formats

Threat Model Spec supports two JSON formats:

| Format | Description | Use Case |
|--------|-------------|----------|
| **ThreatModel** | Canonical format with multiple diagram views | Complete threat models with shared metadata |
| **DiagramIR** | Single-diagram format | Simple use cases, individual diagrams |

## ThreatModel (Recommended)

The `ThreatModel` format is the canonical representation for complete threat models:

```json
{
  "id": "unique-threat-model-id",
  "title": "Threat Model Title",
  "description": "Overview of the vulnerability or threat scenario",
  "version": "1.0.0",
  "authors": [
    {"name": "Author Name", "email": "author@example.com"}
  ],
  "references": [
    {"title": "CVE Link", "url": "https://...", "type": "cve"}
  ],
  "mappings": { ... },
  "diagrams": [
    {"type": "dfd", ...},
    {"type": "attack-chain", ...},
    {"type": "sequence", ...}
  ]
}
```

### ThreatModel Schema

```go
type ThreatModel struct {
    ID          string        // Required: unique identifier
    Title       string        // Required: human-readable title
    Description string        // Optional: overview of the threat
    Version     string        // Optional: version string
    Authors     []Author      // Optional: contributors
    References  []Reference   // Optional: external links
    Mappings    *Mappings     // Optional: shared framework mappings
    Diagrams    []DiagramView // Required: diagram views
}
```

### DiagramView

Each diagram in a ThreatModel inherits mappings from the parent unless overridden:

```go
type DiagramView struct {
    Type        DiagramType   // Required: dfd, attack-chain, sequence
    Title       string        // Optional: diagram-specific title
    Mappings    *Mappings     // Optional: overrides parent mappings
    // ... diagram-specific fields
}
```

## DiagramIR (Single Diagram)

For simpler use cases, the `DiagramIR` format represents a single diagram:

| Type | Description | Key Fields |
|------|-------------|------------|
| `dfd` | Data Flow Diagram | elements, boundaries, flows |
| `attack-chain` | Attack Chain | elements, attacks, targets |
| `sequence` | Sequence Diagram | actors, messages, phases |

### Base Structure

All diagrams share these common fields:

```json
{
  "type": "dfd | attack-chain | sequence",
  "title": "Diagram Title",
  "description": "Optional description",
  "direction": "right | down | left | up",
  "legend": {
    "show": true,
    "showStride": true,
    "showMitre": true
  },
  "mappings": { ... }
}
```

## DiagramIR Schema

```go
type DiagramIR struct {
    Type        DiagramType   // Required: dfd, attack-chain, sequence
    Title       string        // Required: diagram title
    Description string        // Optional: additional context
    Direction   Direction     // Optional: layout direction
    Legend      *Legend       // Optional: legend configuration
    Mappings    *Mappings     // Optional: framework mappings

    // DFD and Attack Chain fields
    Elements   []Element     // DFD elements
    Boundaries []Boundary    // Trust boundaries
    Flows      []Flow        // Data flows (DFD only)

    // Attack Chain fields
    Attacks []Attack        // Attack steps
    Targets []Target        // High-value targets

    // Sequence Diagram fields
    Actors   []Actor        // Lifelines
    Phases   []Phase        // Attack phases
    Messages []Message      // Interactions
}
```

## Type-Specific Fields

### DFD (Data Flow Diagram)

Required fields:

- `elements` — Processes, data stores, external entities
- `flows` — Data flows between elements

Optional fields:

- `boundaries` — Trust boundaries

### Attack Chain

Required fields:

- `elements` — Attack chain components
- `attacks` — Ordered attack steps

Optional fields:

- `boundaries` — Trust boundaries
- `targets` — High-value targets

### Sequence Diagram

Required fields:

- `actors` — Lifelines/participants
- `messages` — Time-ordered interactions

Optional fields:

- `phases` — Logical groupings of messages

## Direction

Controls diagram layout:

| Value | Description |
|-------|-------------|
| `right` | Left to right (default) |
| `down` | Top to bottom |
| `left` | Right to left |
| `up` | Bottom to top |

## Legend Configuration

```json
{
  "legend": {
    "show": true,
    "showStride": true,
    "showMitre": true,
    "showAssets": true,
    "showElements": true,
    "showBoundaries": true
  }
}
```

## Complete Example

```json
{
  "type": "attack-chain",
  "title": "WebSocket Localhost Takeover",
  "description": "Malicious website exploits localhost WebSocket",
  "direction": "right",
  "legend": {
    "show": true,
    "showStride": true,
    "showMitre": true
  },
  "mappings": {
    "mitreAttack": [
      {"tacticId": "TA0001", "techniqueId": "T1189", "techniqueName": "Drive-by Compromise"}
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
  "boundaries": [
    {"id": "browser-sandbox", "label": "Browser Sandbox", "type": "browser"},
    {"id": "localhost", "label": "Localhost Trust", "type": "localhost"}
  ],
  "attacks": [
    {"step": 1, "from": "attacker", "to": "browser", "label": "Serve malicious page", "mitreTechnique": "T1189"},
    {"step": 2, "from": "browser", "to": "agent", "label": "WebSocket to localhost", "mitreTechnique": "T1557"}
  ],
  "targets": [
    {"elementId": "agent", "classification": "crown-jewel", "impact": "Full agent compromise"}
  ]
}
```

## Validation

The IR validates:

1. Required fields are present for each diagram type
2. Element IDs are unique
3. References (from/to) point to valid elements
4. Attack steps are properly ordered

Use strict validation for additional checks:

```bash
tms validate model.json --strict
```

## Next Steps

- [Element Types](elements.md) — Process, datastore, external entity, etc.
- [Boundary Types](boundaries.md) — Browser, localhost, network, etc.
- [Flow Types](flows.md) — Normal, attack, exfil
- [Framework Mappings](mappings.md) — MITRE, OWASP, STRIDE, etc.
