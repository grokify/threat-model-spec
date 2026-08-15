# Threat Model Specification v0.7.0

This document describes the Threat Model Specification format, a JSON-based intermediate representation for security threat modeling diagrams.

## Overview

A threat model is defined in a single JSON file containing:

- **Metadata**: Title, description, version, authors, phase
- **Assets**: Protected assets with sensitivity classification
- **Scenarios**: What-if attack scenarios with preconditions
- **Risk Assessment**: FAIR-based risk quantification
- **Mappings**: Security framework references (MITRE ATT&CK, OWASP, STRIDE, etc.)
- **Diagrams**: Multiple diagram views (DFD, Attack Chain, Sequence, Attack Tree)
- **Security Lifecycle**: Threat actors, mitigations, detections, response actions
- **Role-Based Guidance**: Red Team, Blue Team, and Remediation guidance
- **Purple Team**: Atomic tests, detection coverage, security metrics
- **Supply Chain**: SBOM, VEX statements, dependency risks
- **Attack Graphs**: Path analysis and reachability
- **Agentic AI Modeling**: Agent capabilities, execution context, credential flows (v0.7.0)

## What's New in v0.7.0

### Agentic AI Threat Modeling

Model AI agent capabilities and execution contexts, for reasoning about what an attacker could do if an agent is compromised or manipulated.

`AgentCapabilities` describes an agent's tools, permissions, sandboxing, and approval controls:

```json
{
  "agentCapabilities": {
    "tools": [
      {
        "name": "system.run",
        "capabilityType": "shell-access",
        "enabled": true,
        "requiresApproval": true,
        "riskLevel": "high",
        "asiIds": ["ASI02:2026"]
      }
    ],
    "permissions": [
      {"resource": "filesystem", "actions": ["read", "write"], "scope": "/workspace/*"}
    ],
    "sandboxLevel": "container",
    "requiresApproval": ["shell-access", "network-access"],
    "approvalBypassable": false,
    "networkRestrictions": {
      "internetAccess": true,
      "localhostAccess": false,
      "allowedHosts": ["api.example.com"]
    }
  }
}
```

`ExecutionContext` describes the runtime environment and privileges under which code (agent or otherwise) executes:

```json
{
  "executionContext": {
    "environmentType": "container",
    "privilegeLevel": "restricted",
    "user": "app",
    "workingDirectory": "/app"
  }
}
```

New boundary types for agent modeling:

| Type | Description |
|------|-------------|
| `container` | Container boundary |
| `sandbox` | Application sandbox boundary |
| `agent` | AI agent execution boundary |
| `origin` | Browser same-origin boundary |

### Credential Flow Tracking

`CredentialFlow` tracks a credential's lifecycle through a system, for modeling token exfiltration and replay attacks:

```json
{
  "credentialFlows": [
    {
      "id": "session-token",
      "name": "Session Bearer Token",
      "type": "bearer",
      "assetId": "asset-user-session",
      "expirationDuration": "24h",
      "stages": [
        {"stage": "created", "elementId": "auth-server"},
        {
          "stage": "transmitted",
          "elementId": "websocket-gateway",
          "transportProtocol": "wss",
          "transportMechanism": "websocket-message"
        },
        {"stage": "exfiltrated", "elementId": "attacker", "description": "Leaked via CSWSH"}
      ]
    }
  ]
}
```

Credential lifecycle stages: `created`, `stored`, `transmitted`, `exfiltrated`, `reused`, `revoked`.

### Attack Patterns

`AttackPattern` captures a reusable attack template — prerequisites, attack chain, vulnerable/secure code, and detection patterns — that can be referenced from multiple threat models:

```json
{
  "attackPatterns": [
    {
      "id": "cswsh-localhost-takeover",
      "name": "Cross-Site WebSocket Hijacking via Localhost Trust",
      "type": "cswsh",
      "prerequisites": ["WebSocket endpoint trusts localhost without origin validation"],
      "cweIds": ["CWE-346"],
      "mitreTechniques": ["T1189"],
      "owaspIds": ["API2:2023"]
    }
  ]
}
```

### WebSocket Security

`WebSocketConfig` models a WebSocket endpoint's security posture, including known vulnerability classes:

```json
{
  "network": {
    "webSocket": {
      "protocol": "ws",
      "endpoint": "/ws",
      "allowedOrigins": [],
      "originValidation": false,
      "authenticationRequired": false
    },
    "allowedOrigins": ["https://example.com"],
    "rateLimitRps": 100
  }
}
```

WebSocket vulnerability types: `cswsh`, `no-origin-validation`, `no-rate-limit`, `no-authentication`, `weak-authentication`, `no-encryption`, `message-injection`, `denial-of-service`.

New flow types for attack patterns:

| Type | Description |
|------|-------------|
| `credential` | Credential/token transmission |
| `websocket` | WebSocket connection |
| `cswsh` | Cross-Site WebSocket Hijacking |
| `lateral` | Lateral movement |

### Trust Modeling

Boundaries can now record an implicit trust assumption and how it could be violated — the mechanism used to model the OpenClaw-style "localhost is trusted" flaw:

```json
{
  "boundaries": [
    {
      "id": "localhost",
      "type": "localhost",
      "implicitlyTrusted": true,
      "trustAssumption": "Localhost connections trusted without authentication",
      "trustViolationRisk": "CSWSH bypasses localhost restriction via browser",
      "authenticationRequired": false
    }
  ]
}
```

### Evaluation Package

The new `evaluation` package integrates [structured-evaluation](https://github.com/plexusone/structured-evaluation) for LLM-as-Judge workflows over threat models, vulnerability articles, and diagrams:

```go
import "github.com/grokify/threat-model-spec/evaluation"

// Load embedded rubrics
rubric, _ := evaluation.ThreatModelRubric()
rubric, _ := evaluation.VulnerabilityArticleRubric()
rubric, _ := evaluation.DiagramRubric()

// Convert evaluation results to structured-evaluation reports
report := result.ToEvaluationReport("threat-model.json")
claimsReport := result.ToClaimsReport("threat-model.json")
```

## New Types (v0.7.0)

| Type | Description |
|------|-------------|
| `AgentCapabilities` | AI agent tool access, permissions, sandboxing, and approval controls |
| `ExecutionContext` | Runtime environment and privilege level |
| `CredentialFlow` | Credential/token lifecycle tracking |
| `AttackPattern` | Reusable attack pattern templates |
| `WebSocketConfig` | WebSocket security configuration and known vulnerability types |

## Formats

| Format | Schema | Description |
|--------|--------|--------------|
| ThreatModel | `threat-model.schema.json` | Full threat model with multiple diagrams |
| DiagramIR | `diagram.schema.json` | Single standalone diagram |

## ThreatModel

The canonical format for complete threat models.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the threat model |
| `title` | string | Human-readable title |
| `diagrams` | array | Array of DiagramView objects |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Detailed description |
| `version` | string | Semantic version of the threat model |
| `phase` | enum | SDLC phase |
| `authors` | array | List of Author objects |
| `references` | array | External references |
| `mappings` | object | Shared framework mappings |
| `assets` | array | Protected assets |
| `scenarios` | array | What-if attack scenarios |
| `threatActors` | array | Adversary profiles |
| `assumptions` | array | Security assumptions |
| `prerequisites` | array | Attack prerequisites |
| `mitigations` | array | Shared mitigations |
| `redTeam` | object | Red team exploitation guidance |
| `blueTeam` | object | Blue team defense guidance |
| `remediation` | object | Developer remediation guidance |
| `playbooks` | array | Incident response playbooks |
| `testSuites` | array | app-test-spec references |
| `riskAssessment` | object | FAIR risk assessment |
| `businessImpact` | object | Business impact analysis |
| `epssData` | array | EPSS vulnerability scores |
| `atomicTests` | array | Atomic Red Team mappings |
| `detectionCoverage` | object | ATT&CK coverage matrix |
| `metrics` | object | Security metrics |
| `sbom` | object | SBOM reference |
| `vexStatements` | array | VEX statements |
| `dependencyRisks` | array | Dependency vulnerabilities |
| `credentialFlows` | array | Credential lifecycle tracking (v0.7.0) |
| `attackPatterns` | array | Reusable attack pattern templates (v0.7.0) |

Diagram-level elements gained `agentCapabilities` and `executionContext` (v0.7.0); boundaries gained `implicitlyTrusted`, `trustAssumption`, `trustViolationRisk`, and `authenticationRequired` (v0.7.0); the diagram-level `network` object gained `webSocket`, `allowedOrigins`, and `rateLimitRps` (v0.7.0).

## JSON Schemas

- [threat-model.schema.json](./threat-model.schema.json)
- [diagram.schema.json](./diagram.schema.json)

## Migration from v0.6.0

v0.7.0 is fully backward compatible with v0.6.0. All new fields are optional.

To take advantage of new features:

1. Model AI agent components with `agentCapabilities` and `executionContext`
2. Track credential lifecycles with `credentialFlows`
3. Model WebSocket endpoints with `network.webSocket` and the new WebSocket-specific vulnerability types
4. Record implicit trust assumptions on boundaries (`implicitlyTrusted`, `trustAssumption`, `trustViolationRisk`)
5. Reuse attack templates across models with `attackPatterns`
6. Grade threat models and vulnerability articles with the `evaluation` package
