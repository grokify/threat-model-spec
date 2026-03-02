# Boundary Types

Trust boundaries define security perimeters in DFD and Attack Chain diagrams.

## Overview

| Type | Description | Color |
|------|-------------|-------|
| `browser` | Browser sandbox | Blue |
| `localhost` | Localhost implicit trust | Purple |
| `network` | Network zone | Green |
| `cloud` | Cloud environment | Cyan |
| `breached` | Compromised boundary | Dark red |

## Boundary Structure

```json
{
  "id": "unique-id",
  "label": "Display Name",
  "type": "localhost",
  "parentId": "parent-boundary-id",
  "description": "Optional description"
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `label` | string | Yes | Display name |
| `type` | BoundaryType | Yes | Boundary type |
| `parentId` | string | No | Parent boundary ID |
| `description` | string | No | Additional context |

## Boundary Types

### Browser

The browser sandbox boundary.

```json
{"id": "browser-sandbox", "label": "Browser Sandbox", "type": "browser"}
```

**Use for:** Browser security boundaries, same-origin policies

### Localhost

The localhost implicit trust boundary.

```json
{"id": "localhost-trust", "label": "Localhost Trust Zone", "type": "localhost"}
```

**Use for:** Local services, localhost-only APIs, implicit trust zones

### Network

A network zone boundary.

```json
{"id": "dmz", "label": "DMZ", "type": "network"}
```

**Use for:** DMZ, internal networks, VPCs, subnets

### Cloud

A cloud environment boundary.

```json
{"id": "aws-vpc", "label": "AWS VPC", "type": "cloud"}
```

**Use for:** Cloud environments, containers, serverless

### Breached

A compromised boundary (for attack diagrams).

```json
{"id": "compromised", "label": "Compromised Zone", "type": "breached"}
```

**Use for:** Indicating security boundary violations

## Nesting Elements in Boundaries

Use `parentId` on elements to place them inside boundaries:

```json
{
  "boundaries": [
    {"id": "localhost", "label": "Localhost Trust", "type": "localhost"}
  ],
  "elements": [
    {
      "id": "agent",
      "label": "AI Agent",
      "type": "agent",
      "parentId": "localhost"
    },
    {
      "id": "gateway",
      "label": "API Gateway",
      "type": "gateway",
      "parentId": "localhost"
    }
  ]
}
```

## Nested Boundaries

Boundaries can be nested using `parentId`:

```json
{
  "boundaries": [
    {"id": "network", "label": "Internal Network", "type": "network"},
    {"id": "secure-zone", "label": "Secure Zone", "type": "network", "parentId": "network"}
  ]
}
```

## Complete Example

```json
{
  "type": "dfd",
  "title": "System Architecture",
  "boundaries": [
    {
      "id": "browser-sandbox",
      "label": "Browser Sandbox",
      "type": "browser",
      "description": "Browser same-origin security boundary"
    },
    {
      "id": "localhost",
      "label": "Localhost Trust Zone",
      "type": "localhost",
      "description": "Implicit trust for localhost connections"
    },
    {
      "id": "cloud",
      "label": "Cloud Infrastructure",
      "type": "cloud"
    }
  ],
  "elements": [
    {"id": "browser", "label": "Browser", "type": "browser", "parentId": "browser-sandbox"},
    {"id": "agent", "label": "AI Agent", "type": "agent", "parentId": "localhost"},
    {"id": "gateway", "label": "Gateway", "type": "gateway", "parentId": "localhost"},
    {"id": "api", "label": "Cloud API", "type": "api", "parentId": "cloud"}
  ]
}
```

## D2 Styling

Trust boundaries use colored containers in D2:

| Type | Border Color | Background |
|------|--------------|------------|
| browser | Blue | Light blue |
| localhost | Purple | Light purple |
| network | Green | Light green |
| cloud | Cyan | Light cyan |
| breached | Dark red | Light red |

See [Trust Boundary Styles](../styles/trust-boundaries.md) for D2 class details.
