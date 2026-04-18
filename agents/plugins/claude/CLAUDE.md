# Threat Model Diagrams Plugin

This plugin provides agents for creating security threat modeling diagrams using D2.

## Available Agents

### dfd-creator
Creates Data Flow Diagrams with numbered flows, trust boundaries, and proper legends.
- Generates both normal operation and attack flow variants
- Uses consistent color coding for element types
- Applies layout optimization best practices

### attack-flow-visualizer
Creates attack chain diagrams with MITRE ATT&CK and STRIDE annotations.
- Maps attack steps to framework tactics/techniques
- Highlights crown jewels and exfiltration paths
- Uses red color coding for attack flows

### diagram-quality-reviewer
Reviews diagrams for layout quality, whitespace, and legend clarity.
- Checks aspect ratio and whitespace metrics
- Detects color conflicts in legends
- Verifies arrow visibility and label clarity

## Available Commands

### /create-dfd
Create a Data Flow Diagram for threat modeling.

```bash
/create-dfd myapp              # Create both normal and attack DFDs
/create-dfd myapp --type normal   # Normal operation only
/create-dfd myapp --type attack   # Attack flow only
```

## Skills

### numbered-flow-creation
Guidelines for creating numbered data flow sequences.
- Use numbers (1, 2, 3) for primary flows
- Use letters (A, B, C) for secondary flows
- Red color for attack flows, green/blue for normal

### legend-design
Best practices for legend clarity.
- Always use `near: bottom-center`
- Describe what colors apply to (box fill, arrow, border)
- Avoid color conflicts between categories

### layout-optimization
Guidelines for reducing whitespace and improving clarity.
- Remove `grid-columns` from connected elements
- Use `grid-columns` in legends
- Keep nesting depth ≤ 3

## Color Reference

### STRIDE Categories (Box Fill)

| Category | Fill | Stroke |
|----------|------|--------|
| Spoofing | #ffebee | #c62828 |
| Tampering | #fff3e0 | #ef6c00 |
| Repudiation | #f3e5f5 | #7b1fa2 |
| Info Disclosure | #e3f2fd | #1565c0 |
| DoS | #fce4ec | #c2185b |
| Elevation | #e8f5e9 | #2e7d32 |

### ATT&CK Tactics (Arrow Color - Blue Gradient)

| Tactic | Fill | Stroke |
|--------|------|--------|
| TA0001 Initial Access | #e3f2fd | #1976d2 |
| TA0006 Credential Access | #bbdefb | #1565c0 |
| TA0009 Collection | #90caf9 | #0d47a1 |
| TA0010 Exfiltration | #5c6bc0 | #283593 |

### Assets (Gold/Teal)

| Type | Fill | Stroke | Width |
|------|------|--------|-------|
| Crown Jewel | #fff8e1 | #ff8f00 | 3 |
| High Value | #e0f2f1 | #00897b | 2 |

### Trust Boundaries

| Boundary | Stroke | Fill |
|----------|--------|------|
| Browser | #1565c0 | #e3f2fd |
| Localhost | #7b1fa2 | #f3e5f5 |
| Network | #ef6c00 | #fff3e0 |

## Dependencies

- **d2** (required): D2 diagramming language CLI
- **rsvg-convert** (optional): Convert SVG to PNG for documents
