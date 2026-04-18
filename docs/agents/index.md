# AI Agents

Threat Model Spec includes AI agent specifications for automated diagram creation and quality review.

## Overview

The `agents/` directory contains reusable specifications that can be used with AI coding assistants to create threat model diagrams.

| Agent | Description |
|-------|-------------|
| `dfd-creator` | Creates Data Flow Diagrams with numbered flows and trust boundaries |
| `attack-flow-visualizer` | Creates attack chain diagrams with MITRE ATT&CK annotations |
| `diagram-quality-reviewer` | Reviews diagrams for layout quality and legend clarity |

## Claude Code Plugin

A complete Claude Code plugin is available in `agents/plugins/claude/`.

### Installation

```bash
claude plugins add ./agents/plugins/claude
```

### Available Commands

| Command | Description |
|---------|-------------|
| `/create-dfd <name>` | Create a Data Flow Diagram |
| `/create-dfd <name> --type normal` | Normal operation flows only |
| `/create-dfd <name> --type attack` | Attack flows only |

### Skills

The plugin includes reusable skills:

| Skill | Description |
|-------|-------------|
| `numbered-flow-creation` | Guidelines for numbered data flow sequences |
| `legend-design` | Best practices for legend clarity |
| `layout-optimization` | Guidelines for reducing whitespace |

## Agent Specifications

Agent specifications are located in `agents/specs/` and can be adapted for other AI assistants.

### dfd-creator

Creates Data Flow Diagrams with:

- Numbered flows (1, 2, 3 for primary; A, B, C for secondary)
- Trust boundary visualization
- Color-coded element types
- Proper legends with `near: bottom-center`

### attack-flow-visualizer

Creates attack chain diagrams with:

- MITRE ATT&CK tactic/technique mapping
- STRIDE threat annotations
- Crown jewel highlighting
- Exfiltration path visualization

### diagram-quality-reviewer

Reviews diagrams for:

- Aspect ratio and whitespace metrics
- Color conflicts in legends
- Arrow visibility and label clarity
- Nesting depth (recommended ≤ 3)

## Color Reference

### STRIDE Categories (Box Fill)

| Category | Fill | Stroke |
|----------|------|--------|
| Spoofing | `#ffebee` | `#c62828` |
| Tampering | `#fff3e0` | `#ef6c00` |
| Repudiation | `#f3e5f5` | `#7b1fa2` |
| Info Disclosure | `#e3f2fd` | `#1565c0` |
| DoS | `#fce4ec` | `#c2185b` |
| Elevation | `#e8f5e9` | `#2e7d32` |

### ATT&CK Tactics (Arrow Color)

| Tactic | Fill | Stroke |
|--------|------|--------|
| TA0001 Initial Access | `#e3f2fd` | `#1976d2` |
| TA0006 Credential Access | `#bbdefb` | `#1565c0` |
| TA0009 Collection | `#90caf9` | `#0d47a1` |
| TA0010 Exfiltration | `#5c6bc0` | `#283593` |

### Assets

| Type | Fill | Stroke | Width |
|------|------|--------|-------|
| Crown Jewel | `#fff8e1` | `#ff8f00` | 3 |
| High Value | `#e0f2f1` | `#00897b` | 2 |
