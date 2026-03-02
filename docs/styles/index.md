# D2 Styles Overview

Threat Model Spec includes a comprehensive D2 style library for creating visually consistent threat modeling diagrams.

## Style Files

| File | Contents |
|------|----------|
| `stride.d2` | STRIDE threat badges and boxes |
| `dfd.d2` | DFD element styles |
| `trustboundary.d2` | Trust boundary containers |
| `attackflow.d2` | Attack flow arrow styles |
| `all.d2` | Combined import for all styles |

## Installation

Copy the style files to your project:

```bash
mkdir -p d2/styles
curl -o d2/styles/all.d2 https://raw.githubusercontent.com/grokify/threat-model-spec/main/d2/styles/all.d2
# ... or copy all style files
```

## Usage

Import styles at the top of your D2 file:

```d2
# Import all styles
...d2/styles/all.d2

# Or import specific styles
...d2/styles/stride.d2
...d2/styles/dfd.d2
```

Apply classes to elements:

```d2
attacker: Threat Actor {
  class: external-entity-malicious
}

spoofing-threat: "S - Identity Spoofing" {
  class: threat-box-spoofing
}
```

## Color Scheme

### STRIDE Colors

| Category | Primary | Background |
|----------|---------|------------|
| Spoofing | `#c62828` (Red) | `#ffebee` |
| Tampering | `#f9a825` (Yellow) | `#fffde7` |
| Repudiation | `#7b1fa2` (Purple) | `#f3e5f5` |
| Info Disclosure | `#1565c0` (Blue) | `#e3f2fd` |
| DoS | `#d84315` (Orange) | `#fbe9e7` |
| Elevation | `#2e7d32` (Green) | `#e8f5e9` |

### Trust Boundary Colors

| Type | Color |
|------|-------|
| Browser | Blue |
| Localhost | Purple |
| Network | Green |
| Cloud | Cyan |
| Breached | Dark red |

## Quick Reference

```d2
# STRIDE threats
threat: "S - Spoofing" { class: threat-box-spoofing }

# DFD elements
server: Web Server { class: process }
db: Database { class: datastore }
attacker: Attacker { class: external-entity-malicious }

# Trust boundaries
browser-sandbox: Browser Sandbox { class: trust-boundary-browser }

# Attack flows
attacker -> server: Attack { class: attack-flow }
server -> attacker: Exfil { class: exfil-flow }
```

## Generated Diagrams

The `tms` CLI automatically applies these styles when generating D2:

```bash
tms generate model.json -o diagram.d2 --svg
```

## Next Steps

- [STRIDE Styles](stride.md) — Threat badges and boxes
- [DFD Styles](dfd.md) — Element types
- [Trust Boundaries](trust-boundaries.md) — Security perimeters
- [Attack Flows](attack-flows.md) — Flow styling
