# STRIDE Styles

Color-coded styles for STRIDE threat annotations.

## Overview

STRIDE styles come in two variants:

- **Badges** — Small inline markers (`threat-*`)
- **Boxes** — Larger callout annotations (`threat-box-*`)

## Badge Classes

For compact inline threat indicators:

| Class | Category | Color |
|-------|----------|-------|
| `threat-spoofing` | Spoofing | Red |
| `threat-tampering` | Tampering | Yellow |
| `threat-repudiation` | Repudiation | Purple |
| `threat-info-disclosure` | Info Disclosure | Blue |
| `threat-dos` | Denial of Service | Orange |
| `threat-elevation` | Elevation of Privilege | Green |

### Usage

```d2
...d2/styles/stride.d2

s-badge: "S" { class: threat-spoofing }
t-badge: "T" { class: threat-tampering }
i-badge: "I" { class: threat-info-disclosure }
```

## Box Classes

For detailed threat annotations:

| Class | Category | Color |
|-------|----------|-------|
| `threat-box-spoofing` | Spoofing | Red |
| `threat-box-tampering` | Tampering | Yellow |
| `threat-box-repudiation` | Repudiation | Purple |
| `threat-box-info-disclosure` | Info Disclosure | Blue |
| `threat-box-dos` | Denial of Service | Orange |
| `threat-box-elevation` | Elevation of Privilege | Green |

### Usage

```d2
...d2/styles/stride.d2

spoofing: |md
  **S - Spoofing**
  Attacker impersonates legitimate client
| { class: threat-box-spoofing }

info-disc: |md
  **I - Information Disclosure**
  API keys exposed via WebSocket
| { class: threat-box-info-disclosure }
```

## Color Reference

### Spoofing (Red)

```
Primary:    #c62828
Background: #ffebee
Text:       #b71c1c
```

### Tampering (Yellow)

```
Primary:    #f9a825
Background: #fffde7
Text:       #f57f17
```

### Repudiation (Purple)

```
Primary:    #7b1fa2
Background: #f3e5f5
Text:       #6a1b9a
```

### Information Disclosure (Blue)

```
Primary:    #1565c0
Background: #e3f2fd
Text:       #0d47a1
```

### Denial of Service (Orange)

```
Primary:    #d84315
Background: #fbe9e7
Text:       #bf360c
```

### Elevation of Privilege (Green)

```
Primary:    #2e7d32
Background: #e8f5e9
Text:       #1b5e20
```

## Complete Example

```d2
...d2/styles/stride.d2

direction: right

# Elements
auth-service: Auth Service
api-gateway: API Gateway
database: Database

# STRIDE threat annotations
s-threat: |md
  **S - Spoofing**
  No origin validation allows
  malicious sites to connect
| { class: threat-box-spoofing }

i-threat: |md
  **I - Information Disclosure**
  API keys returned in response
| { class: threat-box-info-disclosure }

e-threat: |md
  **E - Elevation of Privilege**
  Localhost bypass grants
  full agent access
| { class: threat-box-elevation }

# Connect threats to elements
s-threat -> api-gateway: affects
i-threat -> database: affects
e-threat -> auth-service: affects
```

## Go Integration

Use the `stride` package to get D2 class names:

```go
import "github.com/grokify/threat-model-spec/stride"

threat := stride.Spoofing
fmt.Println(threat.D2Class())     // threat-spoofing
fmt.Println(threat.D2BoxClass())  // threat-box-spoofing
fmt.Println(threat.Color())       // #c62828
```
