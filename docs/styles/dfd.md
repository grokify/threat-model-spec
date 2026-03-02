# DFD Styles

Styles for Data Flow Diagram elements.

## Element Classes

| Class | Element | Shape |
|-------|---------|-------|
| `process` | Processing component | Rectangle |
| `datastore` | Data storage | Cylinder |
| `external-entity` | External actor | Rectangle (dashed) |
| `external-entity-malicious` | Malicious actor | Red dashed |
| `gateway` | API gateway | Hexagon |
| `browser` | Web browser | Blue rectangle |
| `agent` | AI/software agent | Purple rectangle |
| `api` | API endpoint | Green rectangle |

## Variants

### Compromised Elements

| Class | Description |
|-------|-------------|
| `process-compromised` | Compromised process |
| `datastore-compromised` | Compromised datastore |

### Sensitive Elements

| Class | Description |
|-------|-------------|
| `datastore-sensitive` | Sensitive data store |

## Usage

```d2
...d2/styles/dfd.d2

# Standard elements
web-server: Web Server { class: process }
database: Database { class: datastore }
user: User { class: external-entity }

# Attacker
attacker: Threat Actor { class: external-entity-malicious }

# Specialized elements
browser: Victim Browser { class: browser }
agent: AI Agent { class: agent }
gateway: API Gateway { class: gateway }
api: REST API { class: api }

# Compromised
compromised-server: Pwned Server { class: process-compromised }

# Sensitive
credentials: Credentials { class: datastore-sensitive }
```

## Complete Example

```d2
...d2/styles/dfd.d2
...d2/styles/trustboundary.d2

direction: right

# Trust boundaries
browser-sandbox: Browser Sandbox {
  class: trust-boundary-browser

  browser: Victim Browser { class: browser }
}

localhost-zone: Localhost Trust {
  class: trust-boundary-localhost

  gateway: Gateway { class: gateway }
  agent: AI Agent { class: agent }
  creds: API Keys { class: datastore-sensitive }
}

# External
attacker: Attacker { class: external-entity-malicious }
cloud-api: Cloud API { class: api }

# Flows
attacker -> browser: Malicious page
browser -> gateway: WebSocket
gateway -> agent: Commands
agent -> creds: Read
agent -> cloud-api: API calls
```

## Color Reference

### Process

```
Fill:   #e3f2fd (light blue)
Stroke: #1976d2 (blue)
```

### Datastore

```
Fill:   #fff3e0 (light orange)
Stroke: #f57c00 (orange)
Shape:  cylinder
```

### External Entity

```
Fill:   #f5f5f5 (light gray)
Stroke: #616161 (gray)
Style:  dashed
```

### Malicious Entity

```
Fill:   #ffebee (light red)
Stroke: #c62828 (red)
Style:  dashed
```

### Browser

```
Fill:   #e3f2fd (light blue)
Stroke: #1565c0 (blue)
```

### Agent

```
Fill:   #f3e5f5 (light purple)
Stroke: #7b1fa2 (purple)
```

### Gateway

```
Fill:   #e8f5e9 (light green)
Stroke: #2e7d32 (green)
Shape:  hexagon
```
