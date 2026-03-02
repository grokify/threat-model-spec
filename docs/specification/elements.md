# Element Types

Elements are the core components in DFD and Attack Chain diagrams.

## Overview

| Type | Description | D2 Style |
|------|-------------|----------|
| `process` | Processing component | Rectangle |
| `datastore` | Data storage | Cylinder |
| `external-entity` | External actor/system | Rectangle (dashed) |
| `gateway` | API gateway/proxy | Hexagon |
| `browser` | Web browser | Rectangle (blue) |
| `agent` | AI/software agent | Rectangle (purple) |
| `api` | API endpoint | Rectangle (green) |

## Element Structure

```json
{
  "id": "unique-id",
  "label": "Display Name",
  "type": "process",
  "parentId": "boundary-id",
  "classification": "high",
  "strideThreats": ["S", "T"],
  "description": "Optional description"
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `label` | string | Yes | Display name |
| `type` | ElementType | Yes | Element type |
| `parentId` | string | No | Containing boundary ID |
| `classification` | AssetClassification | No | Asset sensitivity |
| `strideThreats` | []STRIDEThreat | No | Applicable STRIDE threats |
| `description` | string | No | Additional context |

## Element Types

### Process

A processing component that transforms data.

```json
{"id": "web-server", "label": "Web Server", "type": "process"}
```

**Use for:** Application servers, microservices, business logic

### Datastore

A component that stores data.

```json
{"id": "db", "label": "Database", "type": "datastore", "classification": "crown-jewel"}
```

**Use for:** Databases, file systems, caches, message queues

### External Entity

An actor or system outside the trust boundary.

```json
{"id": "attacker", "label": "Threat Actor", "type": "external-entity"}
```

**Use for:** Users, attackers, third-party services

### Gateway

An API gateway or proxy component.

```json
{"id": "gateway", "label": "API Gateway", "type": "gateway"}
```

**Use for:** API gateways, load balancers, reverse proxies

### Browser

A web browser component.

```json
{"id": "browser", "label": "Victim Browser", "type": "browser"}
```

**Use for:** Web browsers, browser extensions

### Agent

An AI or software agent.

```json
{"id": "agent", "label": "AI Agent", "type": "agent", "classification": "crown-jewel"}
```

**Use for:** AI assistants, automated systems, bots

### API

An API endpoint.

```json
{"id": "rest-api", "label": "REST API", "type": "api"}
```

**Use for:** REST endpoints, GraphQL, WebSocket servers

## Asset Classification

Indicate asset sensitivity:

| Value | Description |
|-------|-------------|
| `crown-jewel` | Most critical assets |
| `high` | High-value assets |
| `medium` | Standard assets |
| `low` | Low-sensitivity assets |

```json
{
  "id": "credentials",
  "label": "Credential Store",
  "type": "datastore",
  "classification": "crown-jewel"
}
```

## STRIDE Threats

Annotate elements with applicable threats:

```json
{
  "id": "auth-service",
  "label": "Auth Service",
  "type": "process",
  "strideThreats": ["S", "E"]
}
```

| Code | Threat |
|------|--------|
| `S` | Spoofing |
| `T` | Tampering |
| `R` | Repudiation |
| `I` | Information Disclosure |
| `D` | Denial of Service |
| `E` | Elevation of Privilege |

## Complete Example

```json
{
  "elements": [
    {
      "id": "attacker",
      "label": "Threat Actor",
      "type": "external-entity",
      "description": "Malicious actor controlling exploit website"
    },
    {
      "id": "browser",
      "label": "Victim Browser",
      "type": "browser",
      "parentId": "browser-sandbox"
    },
    {
      "id": "agent",
      "label": "AI Agent",
      "type": "agent",
      "parentId": "localhost",
      "classification": "crown-jewel",
      "strideThreats": ["S", "I", "E"]
    },
    {
      "id": "credentials",
      "label": "API Keys",
      "type": "datastore",
      "parentId": "localhost",
      "classification": "crown-jewel",
      "strideThreats": ["I"]
    }
  ]
}
```
