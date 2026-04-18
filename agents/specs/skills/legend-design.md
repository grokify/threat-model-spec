---
name: legend-design
description: Best practices for designing clear, informative legends in threat model diagrams
triggers: [legend, color, key, annotation]
dependencies: [d2]
---

# Legend Design

Best practices for creating legends that clearly explain diagram elements.

## Legend Positioning

Always position the legend outside the main diagram flow:

```d2
legend: Legend {
  near: bottom-center  # Recommended
  # Alternatives: top-center, bottom-left, bottom-right
}
```

**Why**: Using `near:` prevents the legend from displacing main content and reduces whitespace.

## Legend Structure

### Horizontal Layout

Use `grid-columns` to arrange items horizontally:

```d2
legend: Legend {
  near: bottom-center
  grid-columns: 4  # Adjust based on number of items

  item1: "First" { ... }
  item2: "Second" { ... }
  item3: "Third" { ... }
  item4: "Fourth" { ... }
}
```

### Nested Categories

Group related items:

```d2
legend: Legend {
  near: bottom-center
  grid-columns: 3

  stride: "STRIDE (box fill)" {
    grid-columns: 3
    s: S { style.fill: "#ffebee" }
    t: T { style.fill: "#fff3e0" }
    r: R { style.fill: "#f3e5f5" }
  }

  mitre: "ATT&CK (arrow color)" {
    grid-columns: 4
    ta0001: TA0001 { style.fill: "#e3f2fd" }
    ta0006: TA0006 { style.fill: "#bbdefb" }
  }

  assets: "Assets (data store)" {
    grid-columns: 2
    crown: Crown { style.fill: "#fff8e1" }
    high: High { style.fill: "#e0f2f1" }
  }
}
```

## Descriptive Labels

**Always describe what the color applies to**:

| ❌ Unclear | ✅ Clear |
|-----------|---------|
| STRIDE | STRIDE (box fill) |
| ATT&CK | ATT&CK (arrow color) |
| Assets | Assets (data store) |
| Boundary | Trust Boundary (border) |
| Flow | Attack flow (red arrows) |

## Color Families

Use distinct color families for different semantic categories:

### STRIDE Threats (Semantic Colors)

| Category | Fill | Stroke | Rationale |
|----------|------|--------|-----------|
| Spoofing | #ffebee | #c62828 | Red = danger/identity |
| Tampering | #fff3e0 | #ef6c00 | Orange = modification |
| Repudiation | #f3e5f5 | #7b1fa2 | Purple = denial |
| Info Disclosure | #e3f2fd | #1565c0 | Blue = information |
| DoS | #fce4ec | #c2185b | Pink = disruption |
| Elevation | #e8f5e9 | #2e7d32 | Green = growth/escalation |

### ATT&CK Tactics (Blue Gradient)

Show progression through kill chain with darkening blues:

| Tactic | Fill | Stroke | Position |
|--------|------|--------|----------|
| TA0001 Initial Access | #e3f2fd | #1976d2 | Early |
| TA0006 Credential Access | #bbdefb | #1565c0 | Middle |
| TA0009 Collection | #90caf9 | #0d47a1 | Late |
| TA0010 Exfiltration | #5c6bc0 | #283593 | Final |

### Assets (Gold/Teal)

| Classification | Fill | Stroke | Width |
|---------------|------|--------|-------|
| Crown Jewel | #fff8e1 | #ff8f00 | 3 |
| High Value | #e0f2f1 | #00897b | 2 |
| Standard | default | default | 1 |

### Trust Boundaries

| Boundary | Stroke | Fill |
|----------|--------|------|
| Browser (Untrusted) | #1565c0 | #e3f2fd |
| Localhost (Trusted) | #7b1fa2 | #f3e5f5 |
| Network | #ef6c00 | #fff3e0 |
| Cloud | #0097a7 | #e0f7fa |

## Avoiding Color Conflicts

**Never use the same color for different meanings**:

| ❌ Conflict | Problem |
|------------|---------|
| Red for STRIDE.S AND Crown Jewel | Is it spoofing or high value? |
| Blue for ATT&CK AND Browser boundary | Ambiguous |
| Green for STRIDE.E AND Normal flow | Confusing |

**Solution**: Use distinct color families:
- Red family → STRIDE.Spoofing only
- Gold family → Assets
- Blue family → ATT&CK or Boundaries (not both)

## Legend Styling

```d2
legend: Legend {
  near: bottom-center
  style: {
    fill: "#fafafa"      # Light background
    stroke: "#e0e0e0"    # Subtle border
    border-radius: 8     # Rounded corners
  }

  # Category containers
  category: "Category Name" {
    style.fill: "#ffffff"  # White background for contrast
  }
}
```

## Element Type Examples

### DFD Elements

```d2
legend: Legend {
  grid-columns: 4

  process: "Process (box)" {
    shape: rectangle
    style.fill: "#e3f2fd"
    style.stroke: "#1976d2"
    style.border-radius: 8
  }

  datastore: "Data Store (cylinder)" {
    shape: cylinder
    style.fill: "#fce4ec"
    style.stroke: "#c2185b"
  }

  external: "External Entity (person)" {
    shape: person
    style.fill: "#e8f5e9"
    style.stroke: "#388e3c"
  }

  boundary: "Trust Boundary (dashed)" {
    style.stroke-dash: 5
    style.stroke: "#7b1fa2"
    style.fill: "#f3e5f5"
  }
}
```

### Flow Types

```d2
legend: Legend {
  grid-columns: 3

  normal: "Normal flow (green)" {
    style.stroke: "#2e7d32"
    style.stroke-width: 2
  }

  secondary: "Alt flow (blue)" {
    style.stroke: "#1565c0"
    style.stroke-width: 2
  }

  attack: "Attack flow (red)" {
    style.stroke: "#c62828"
    style.stroke-width: 3
  }
}
```

## Validation Checklist

- [ ] Legend uses `near:` positioning
- [ ] Legend uses `grid-columns` for horizontal layout
- [ ] All element types explained
- [ ] All color meanings documented
- [ ] Labels describe what is colored (box fill, arrow, border)
- [ ] No color conflicts between categories
- [ ] Consistent color families within categories
