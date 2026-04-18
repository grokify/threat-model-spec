---
name: create-dfd
description: Create a Data Flow Diagram for threat modeling with numbered flows and proper legend
arguments:
  - name: name
    type: string
    required: true
    description: Base name for the diagram files (e.g., "openclaw")
  - name: type
    type: string
    required: false
    default: both
    description: Diagram type - "normal", "attack", or "both"
dependencies: [d2, rsvg-convert]
process:
  - Gather system architecture information
  - Identify trust boundaries and components
  - Map data flows with numbered sequences
  - Create D2 diagram with proper legend
  - Render to SVG and optionally PNG
---

# Create DFD Command

Creates Data Flow Diagrams for threat modeling.

## Usage

```bash
/create-dfd openclaw              # Create both normal and attack DFDs
/create-dfd openclaw --type normal   # Create only normal operation DFD
/create-dfd openclaw --type attack   # Create only attack flow DFD
```

## Output Files

| Type | D2 Source | SVG | PNG |
|------|-----------|-----|-----|
| Normal | {name}_normal.d2 | {name}_normal.svg | {name}_normal.png |
| Attack | {name}_attack.d2 | {name}_attack.svg | {name}_attack.png |

## Process

### 1. Gather Architecture Information

Ask user about:
- System components (processes, data stores, external entities)
- Trust boundaries (browser, localhost, network, cloud)
- Data flows between components
- Crown jewels (high-value assets like API keys, secrets)

### 2. Create Normal Operation DFD

Structure:
```d2
direction: right

title: "DFD: Normal Operation" {
  near: top-center
}

legend: Legend {
  near: bottom-center
  grid-columns: 5
  # Element types and trust boundaries
}

# Trust boundaries as containers
browser-zone: Browser Sandbox { ... }
localhost-zone: Localhost { ... }

# Numbered flows (green for primary, blue for secondary)
user -> app: "1. Action" { style.stroke: "#2e7d32" }
```

### 3. Create Attack Flow DFD

Structure:
```d2
direction: right

title: "DFD: Attack Flow" {
  near: top-center
}

legend: Legend {
  near: bottom-center
  # Include attack flow indicator (red)
}

# Add attacker infrastructure
attacker-c2: Attacker C2 Server { style.fill: "#ffcdd2" }

# Add malicious component in browser
browser-zone: {
  malicious: Malicious Website { style.fill: "#ffcdd2" }
}

# Numbered attack steps (red, thick)
victim -> browser.malicious: "1. Visit page" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}
```

### 4. Render Diagrams

```bash
d2 {name}_normal.d2 {name}_normal.svg
d2 {name}_attack.d2 {name}_attack.svg

# Optional: Convert to PNG for documents
rsvg-convert -w 1600 {name}_normal.svg -o {name}_normal.png
rsvg-convert -w 1600 {name}_attack.svg -o {name}_attack.png
```

### 5. Quality Check

Run diagram quality review:
- Verify arrows are visible
- Check whitespace < 50%
- Confirm legend is clear
- Ensure numbered flows are sequential

## Example Output

### Normal Operation

```d2
direction: right

title: "DFD: Normal Operation" {
  near: top-center
  style.font-size: 32
}

legend: Legend {
  near: bottom-center
  grid-columns: 5

  process: "Process (box)" { shape: rectangle; style.fill: "#e3f2fd" }
  datastore: "Data Store (cylinder)" { shape: cylinder; style.fill: "#fce4ec" }
  external: "External (person)" { shape: person; style.fill: "#e8f5e9" }
  browser-tb: "Browser TB" { style.stroke-dash: 5; style.fill: "#e3f2fd" }
  localhost-tb: "Localhost TB" { style.stroke-dash: 5; style.fill: "#f3e5f5" }
}

user: Developer { shape: person }
ide: IDE { shape: rectangle }

localhost-zone: Localhost {
  style.stroke-dash: 5
  agent: AI Agent { }
  api-keys: API Keys { shape: cylinder }
}

llm-api: LLM API { shape: cloud }

# Primary flow (green)
user -> ide: "1. Write code" { style.stroke: "#2e7d32" }
ide -> localhost-zone.agent: "2. Request" { style.stroke: "#2e7d32" }
localhost-zone.agent -> localhost-zone.api-keys: "3. Get key" { style.stroke: "#2e7d32" }
localhost-zone.agent -> llm-api: "4. LLM call" { style.stroke: "#2e7d32" }
llm-api -> localhost-zone.agent: "5. Response" { style.stroke: "#2e7d32" }
localhost-zone.agent -> ide: "6. Suggestion" { style.stroke: "#2e7d32" }
```

### Attack Flow

```d2
direction: right

title: "DFD: WebSocket Takeover Attack" {
  near: top-center
  style.font-size: 32
}

# Attacker infrastructure
attacker-c2: Attacker C2 { style.fill: "#ffcdd2"; style.stroke: "#b71c1c" }

browser-zone: Browser {
  malicious: Malicious Site { style.fill: "#ffcdd2" }
}

localhost-zone: Localhost {
  gateway: Gateway { }
  agent: Agent { }
  api-keys: API Keys { shape: cylinder; style.fill: "#ffcdd2" }
}

victim: Victim { shape: person }

# Attack steps (red)
victim -> browser-zone.malicious: "1. Visit page" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

browser-zone.malicious -> localhost-zone.gateway: "2. WebSocket" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

localhost-zone.gateway -> localhost-zone.agent: "3. Access" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

localhost-zone.agent -> localhost-zone.api-keys: "4. Steal keys" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

localhost-zone.gateway -> browser-zone.malicious: "5. Return data" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

browser-zone.malicious -> attacker-c2: "6. Exfiltrate" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}
```

## Validation

After creation, verify:
- [ ] Both diagrams render without errors
- [ ] Arrows between elements are visible
- [ ] Legend explains all visual elements
- [ ] Numbered flows are sequential (no gaps)
- [ ] Attack flows use red consistently
- [ ] Normal flows use green/blue consistently
- [ ] Crown jewels are highlighted
