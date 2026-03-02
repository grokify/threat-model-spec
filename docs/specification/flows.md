# Flow Types

Flows represent data movement between elements in DFD diagrams and interactions in sequence diagrams.

## Overview

| Type | Description | D2 Style |
|------|-------------|----------|
| `normal` | Standard data flow | Solid arrow |
| `attack` | Malicious flow | Red dashed arrow |
| `exfil` | Data exfiltration | Orange dashed arrow |

## Flow Structure (DFD)

```json
{
  "from": "source-element-id",
  "to": "destination-element-id",
  "label": "Flow description",
  "type": "normal",
  "bidirectional": false
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | Yes | Source element ID |
| `to` | string | Yes | Destination element ID |
| `label` | string | No | Flow description |
| `type` | FlowType | No | Flow type (default: normal) |
| `bidirectional` | bool | No | Two-way flow |

## Flow Types

### Normal

Standard data flow between components.

```json
{"from": "client", "to": "server", "label": "HTTPS Request", "type": "normal"}
```

**Use for:** API calls, database queries, legitimate data transfer

### Attack

Malicious flow representing an attack vector.

```json
{"from": "attacker", "to": "server", "label": "SQL Injection", "type": "attack"}
```

**Use for:** Attack vectors, exploit attempts, malicious requests

### Exfil

Data exfiltration flow.

```json
{"from": "server", "to": "attacker", "label": "Stolen Data", "type": "exfil"}
```

**Use for:** Data theft, credential exfiltration, unauthorized data access

## Bidirectional Flows

Indicate two-way communication:

```json
{"from": "client", "to": "server", "label": "WebSocket", "bidirectional": true}
```

## Attack Steps (Attack Chain)

For attack chain diagrams, use the `attacks` array instead:

```json
{
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "browser",
      "label": "Serve malicious page",
      "mitreTechnique": "T1189"
    },
    {
      "step": 2,
      "from": "browser",
      "to": "agent",
      "label": "WebSocket connection",
      "mitreTechnique": "T1557"
    }
  ]
}
```

### Attack Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `step` | int | Yes | Sequence number |
| `from` | string | Yes | Source element ID |
| `to` | string | Yes | Target element ID |
| `label` | string | Yes | Attack description |
| `mitreTactic` | MITRETactic | No | MITRE tactic ID |
| `mitreTechnique` | string | No | MITRE technique ID |
| `strideThreats` | []STRIDEThreat | No | STRIDE categories |
| `description` | string | No | Additional context |

## Messages (Sequence Diagram)

For sequence diagrams, use the `messages` array:

```json
{
  "messages": [
    {
      "seq": 1,
      "from": "attacker",
      "to": "victim",
      "label": "Phishing email",
      "type": "attack"
    },
    {
      "seq": 2,
      "from": "victim",
      "to": "attacker",
      "label": "Credentials",
      "type": "exfil"
    }
  ]
}
```

### Message Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `seq` | int | Yes | Sequence number |
| `from` | string | Yes | Source actor ID |
| `to` | string | Yes | Destination actor ID |
| `label` | string | Yes | Message description |
| `type` | FlowType | No | Message type |
| `mitreTechnique` | string | No | MITRE technique ID |
| `note` | bool | No | Self-message note |

## Complete DFD Example

```json
{
  "type": "dfd",
  "title": "API Data Flow",
  "elements": [
    {"id": "client", "label": "Client", "type": "external-entity"},
    {"id": "api", "label": "API Server", "type": "process"},
    {"id": "db", "label": "Database", "type": "datastore"}
  ],
  "flows": [
    {"from": "client", "to": "api", "label": "REST Request"},
    {"from": "api", "to": "db", "label": "SQL Query"},
    {"from": "db", "to": "api", "label": "Results"},
    {"from": "api", "to": "client", "label": "JSON Response"}
  ]
}
```

## Complete Attack Chain Example

```json
{
  "type": "attack-chain",
  "title": "Credential Theft",
  "elements": [
    {"id": "attacker", "label": "Attacker", "type": "external-entity"},
    {"id": "phishing", "label": "Phishing Site", "type": "process"},
    {"id": "creds", "label": "Credentials", "type": "datastore"}
  ],
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "phishing",
      "label": "Deploy phishing site",
      "mitreTechnique": "T1566"
    },
    {
      "step": 2,
      "from": "phishing",
      "to": "creds",
      "label": "Harvest credentials",
      "mitreTechnique": "T1110",
      "strideThreats": ["S", "I"]
    }
  ]
}
```
