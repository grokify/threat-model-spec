# Trust Boundary Styles

Styles for trust boundary containers in threat models.

## Boundary Classes

| Class | Type | Color |
|-------|------|-------|
| `trust-boundary` | Generic | Gray |
| `trust-boundary-external` | External | Gray (darker) |
| `trust-boundary-internal` | Internal | Light gray |
| `trust-boundary-dmz` | DMZ | Yellow |
| `trust-boundary-browser` | Browser sandbox | Blue |
| `trust-boundary-localhost` | Localhost trust | Purple |
| `trust-boundary-breached` | Compromised | Red |

## Usage

```d2
...d2/styles/trustboundary.d2

# Browser sandbox
browser-sandbox: Browser Sandbox {
  class: trust-boundary-browser

  # Elements inside the boundary
  browser: Browser
  scripts: JavaScript
}

# Localhost trust zone
localhost: Localhost Trust {
  class: trust-boundary-localhost

  agent: AI Agent
  gateway: Gateway
}

# Breached boundary
compromised: Compromised Zone {
  class: trust-boundary-breached

  pwned-server: Pwned Server
}
```

## Color Reference

### Generic Trust Boundary

```
Fill:   #fafafa
Stroke: #9e9e9e (gray)
Style:  dashed
```

### Browser Sandbox

```
Fill:   #e3f2fd (light blue)
Stroke: #1565c0 (blue)
Style:  dashed
```

### Localhost Trust

```
Fill:   #f3e5f5 (light purple)
Stroke: #7b1fa2 (purple)
Style:  dashed
```

### DMZ

```
Fill:   #fffde7 (light yellow)
Stroke: #f9a825 (yellow)
Style:  dashed
```

### Breached

```
Fill:   #ffebee (light red)
Stroke: #b71c1c (dark red)
Style:  dashed, thick
```

## Complete Example

```d2
...d2/styles/all.d2

direction: right

# External (attacker controlled)
external: External Network {
  class: trust-boundary-external

  attacker: Attacker { class: external-entity-malicious }
  malicious-site: Malicious Site { class: process }
}

# Browser sandbox
browser-zone: Browser Sandbox {
  class: trust-boundary-browser

  browser: Victim Browser { class: browser }
}

# DMZ
dmz: DMZ {
  class: trust-boundary-dmz

  web-server: Web Server { class: process }
}

# Localhost (implicit trust)
localhost: Localhost Trust Zone {
  class: trust-boundary-localhost

  agent: AI Agent { class: agent }
  gateway: API Gateway { class: gateway }
  creds: Credentials { class: datastore-sensitive }
}

# Attack flow across boundaries
attacker -> browser: 1. Serve exploit page
browser -> gateway: 2. WebSocket to localhost
gateway -> agent: 3. Execute commands
agent -> creds: 4. Exfiltrate data
```

## Nesting Boundaries

Boundaries can be nested for complex architectures:

```d2
cloud: Cloud Environment {
  class: trust-boundary

  vpc: VPC {
    class: trust-boundary-internal

    private: Private Subnet {
      class: trust-boundary-internal

      database: Database { class: datastore }
    }

    public: Public Subnet {
      class: trust-boundary-dmz

      api: API Server { class: process }
    }
  }
}
```

## Security Implications

Trust boundaries highlight where security controls are needed:

| Boundary Crossing | Required Controls |
|-------------------|-------------------|
| External → Browser | Content Security Policy |
| Browser → Localhost | Origin validation |
| DMZ → Internal | Firewall, authentication |
| Any → Sensitive | Encryption, access control |
