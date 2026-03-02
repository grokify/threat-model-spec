# Attack Flow Styles

Styles for attack flow arrows and connections.

## Flow Classes

| Class | Type | Style |
|-------|------|-------|
| `normal-flow` | Standard data flow | Solid arrow |
| `attack-flow` | Attack vector | Red dashed |
| `exfil-flow` | Data exfiltration | Orange dashed |

## Usage

```d2
...d2/styles/attackflow.d2

# Normal data flow
client -> server: API Request { class: normal-flow }

# Attack flow
attacker -> server: SQL Injection { class: attack-flow }

# Exfiltration
server -> attacker: Stolen Data { class: exfil-flow }
```

## Color Reference

### Normal Flow

```
Stroke: #424242 (dark gray)
Style:  solid
Arrow:  filled
```

### Attack Flow

```
Stroke: #c62828 (red)
Style:  dashed
Arrow:  filled
Width:  2
```

### Exfiltration Flow

```
Stroke: #d84315 (orange)
Style:  dashed
Arrow:  filled
Width:  2
```

## Complete Example

```d2
...d2/styles/all.d2

direction: right

# Elements
attacker: Attacker { class: external-entity-malicious }
browser: Browser { class: browser }
gateway: Gateway { class: gateway }
agent: Agent { class: agent }
creds: Credentials { class: datastore-sensitive }

# Attack chain
attacker -> browser: 1. Malicious page {
  class: attack-flow
  style.stroke: "#c62828"
}

browser -> gateway: 2. WebSocket {
  class: attack-flow
}

gateway -> agent: 3. Commands {
  class: attack-flow
}

agent -> creds: 4. Read {
  class: normal-flow
}

creds -> attacker: 5. Exfiltrate {
  class: exfil-flow
}
```

## Numbered Attack Steps

For attack chain diagrams, number the steps:

```d2
# Step annotations
step1: "① Initial Access" { class: threat-box-spoofing }
step2: "② Execution" { class: threat-box-tampering }
step3: "③ Exfiltration" { class: threat-box-info-disclosure }

# Connect to flows
step1 -> attacker -> browser
step2 -> browser -> agent
step3 -> agent -> attacker
```

## Bidirectional Flows

For two-way communication:

```d2
client <-> server: WebSocket {
  style.stroke: "#1976d2"
}
```

## Flow Labels with Techniques

Include MITRE ATT&CK technique IDs:

```d2
attacker -> browser: |md
  **T1189**
  Drive-by Compromise
| { class: attack-flow }

browser -> gateway: |md
  **T1557**
  Adversary-in-the-Middle
| { class: attack-flow }
```
