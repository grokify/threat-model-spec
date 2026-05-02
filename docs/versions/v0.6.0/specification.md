# Threat Model Specification v0.6.0

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

## What's New in v0.6.0

### OWASP ASI Support

- **Agentic Category**: New `agentic` OWASP category for AI agent threats
- **ASI IDs**: `asiIds` field on Attack struct for ASI mappings
- **Reference Data**: 40 OWASP entries across API, LLM, Web, and ASI lists
- **Validation**: `ValidateOWASPMappings()` for ID verification

### Role-Based Security Guidance

- **Red Team**: `ExploitationGuidance` with steps, tools, and difficulty
- **Blue Team**: `DefenseGuidance` with detection rules, IOCs, and hunting queries
- **Remediation**: `RemediationGuidance` with code patterns and checklists
- **Playbooks**: `IncidentPlaybook` for structured IR procedures

### Risk Quantification

- **FAIR Assessment**: Frequency and loss estimates with ALE calculation
- **Business Impact**: Revenue, customer, regulatory, reputation impacts
- **EPSS Integration**: Exploit Prediction Scoring System data

### Threat Intelligence

- **Enhanced STIX Export**: IOCs, threat actors, detection rules to STIX 2.1
- **KEV Catalog**: CISA Known Exploited Vulnerabilities integration

### Purple Team

- **Atomic Red Team**: Test mappings with validation status
- **Detection Coverage**: MITRE ATT&CK coverage matrix
- **Security Metrics**: MTTD, MTTR, MTTC, detection rates

### Supply Chain Security

- **SBOM Integration**: CycloneDX/SPDX references
- **VEX Statements**: Vulnerability exploitability status
- **Dependency Risks**: Component vulnerability tracking

### Vulnerability Management

- **SSVC Assessment**: CISA prioritization decision trees
- **Priority Decisions**: Track, Track*, Attend, Act

### Attack Path Analysis

- **Attack Graphs**: Graph-based attack surface representation
- **Path Finding**: All paths, shortest path, critical paths
- **Risk Calculation**: Path-based risk scoring
- **Reachability**: Exposure assessment from entry points

## Formats

| Format | Schema | Description |
|--------|--------|-------------|
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
| `redTeam` | object | Red team exploitation guidance (v0.6.0) |
| `blueTeam` | object | Blue team defense guidance (v0.6.0) |
| `remediation` | object | Developer remediation guidance (v0.6.0) |
| `playbooks` | array | Incident response playbooks (v0.6.0) |
| `testSuites` | array | app-test-spec references (v0.6.0) |
| `riskAssessment` | object | FAIR risk assessment (v0.6.0) |
| `businessImpact` | object | Business impact analysis (v0.6.0) |
| `epssData` | array | EPSS vulnerability scores (v0.6.0) |
| `atomicTests` | array | Atomic Red Team mappings (v0.6.0) |
| `detectionCoverage` | object | ATT&CK coverage matrix (v0.6.0) |
| `metrics` | object | Security metrics (v0.6.0) |
| `sbom` | object | SBOM reference (v0.6.0) |
| `vexStatements` | array | VEX statements (v0.6.0) |
| `dependencyRisks` | array | Dependency vulnerabilities (v0.6.0) |

## OWASP Categories (v0.6.0)

| Category | Value | Year | Description |
|----------|-------|------|-------------|
| API Security | `api` | 2023 | API Security Top 10 |
| LLM Applications | `llm` | 2025 | LLM Application Top 10 |
| Web Applications | `web` | 2021 | Web Application Top 10 |
| Agentic Applications | `agentic` | 2026 | Agentic Top 10 (ASI) |

```json
{
  "mappings": {
    "owasp": [
      {"category": "agentic", "id": "ASI02:2026", "name": "Tool Misuse & Exploitation"},
      {"category": "api", "id": "API8:2023", "name": "Security Misconfiguration"}
    ]
  }
}
```

## Attack Struct (v0.6.0 Extensions)

Attack steps now support additional fields:

```json
{
  "step": 6,
  "from": "gateway",
  "to": "agent",
  "label": "Access agent",
  "action": "Send malicious prompt to agent",
  "outcome": "Agent executes unauthorized commands",
  "owaspIds": ["API8:2023"],
  "asiIds": ["ASI02:2026", "ASI03:2026"],
  "atlasTechnique": "AML.T0024",
  "linddunThreats": ["L"],
  "redTeamNotes": "Use prompt injection payload",
  "blueTeamNotes": "Monitor for unusual agent actions",
  "remediationNote": "Implement input validation",
  "testRef": {"suiteId": "security-tests", "testId": "agent-injection-001"},
  "componentRefs": [{"purl": "pkg:npm/vulnerable-lib@1.0.0"}]
}
```

## Role-Based Guidance (v0.6.0)

### Red Team (ExploitationGuidance)

```json
{
  "redTeam": {
    "prerequisites": ["Target must have WebSocket gateway enabled on localhost:9999"],
    "exploitationSteps": [
      {
        "order": 1,
        "action": "Host malicious webpage",
        "tool": "Python HTTP server",
        "expectedResult": "Page accessible to victim"
      }
    ],
    "tools": [
      {"name": "Burp Suite", "purpose": "WebSocket interception", "url": "https://portswigger.net/burp"}
    ],
    "payloadPatterns": [
      {"name": "WebSocket Origin Bypass", "pattern": "new WebSocket('ws://localhost:9999')"}
    ],
    "successIndicators": ["Agent responds to commands", "Data exfiltrated"],
    "difficulty": "low",
    "testRefs": [{"suiteId": "pentest-suite", "testId": "ws-origin-001"}]
  }
}
```

### Blue Team (DefenseGuidance)

```json
{
  "blueTeam": {
    "detectionRules": [
      {
        "name": "Cross-Origin WebSocket Connection",
        "format": "sigma",
        "rule": "title: Cross-Origin WebSocket\\nlogsource:\\n  category: webserver\\ndetection:\\n  selection:\\n    ws_origin|not: 'trusted.example.com'\\n  condition: selection"
      }
    ],
    "iocs": [
      {"type": "pattern", "value": "ws://localhost:*", "confidence": 0.9, "description": "Localhost WebSocket connection"}
    ],
    "logSources": [
      {"name": "WebSocket logs", "location": "/var/log/ws-gateway/", "format": "json"}
    ],
    "huntingQueries": [
      {"name": "Find cross-origin WS", "language": "splunk", "query": "index=ws origin!=trusted.example.com"}
    ],
    "alertThreshold": {"metric": "cross_origin_ws_count", "threshold": 5, "window": "5m", "severity": "high"}
  }
}
```

### Remediation (RemediationGuidance)

```json
{
  "remediation": {
    "codePatterns": [
      {
        "language": "javascript",
        "vulnerable": "wss.on('connection', (ws) => { /* no origin check */ });",
        "secure": "wss.on('connection', (ws, req) => {\\n  if (req.headers.origin !== 'https://trusted.example.com') {\\n    ws.close();\\n    return;\\n  }\\n});"
      }
    ],
    "checklist": [
      {"item": "Validate WebSocket Origin header", "required": true, "category": "input-validation"},
      {"item": "Implement rate limiting", "required": false, "category": "dos-protection"}
    ],
    "libraries": [
      {"name": "helmet", "language": "javascript", "purpose": "Security headers", "url": "https://helmetjs.github.io/"}
    ],
    "configChanges": [
      {"file": "ws-config.json", "key": "allowedOrigins", "value": "[\"https://trusted.example.com\"]"}
    ]
  }
}
```

## Risk Quantification (v0.6.0)

### FAIR Assessment

```json
{
  "riskAssessment": {
    "scenarioName": "WebSocket Localhost Takeover",
    "frequency": {
      "contactFrequency": 100,
      "probabilityOfAction": 0.3,
      "threatEventFrequency": 30,
      "vulnerability": 0.8,
      "lossEventFrequency": 24
    },
    "loss": {
      "primaryLoss": {"amount": 50000, "currency": "USD"},
      "secondaryLoss": {"amount": 200000, "currency": "USD"},
      "totalLoss": {"amount": 250000, "currency": "USD"}
    },
    "annualizedLossExpectancy": {"amount": 6000000, "currency": "USD"}
  }
}
```

### EPSS Data

```json
{
  "epssData": [
    {
      "cve": "CVE-2024-12345",
      "score": 0.85,
      "percentile": 0.97,
      "date": "2026-04-28"
    }
  ]
}
```

## Purple Team (v0.6.0)

### Atomic Red Team Mapping

```json
{
  "atomicTests": [
    {
      "techniqueId": "T1189",
      "testId": "T1189-1",
      "testName": "Drive-by Compromise via Malicious Site",
      "result": "passed",
      "platform": "windows",
      "executedAt": "2026-04-28T10:00:00Z",
      "notes": "Successfully demonstrated attack path"
    }
  ]
}
```

### Detection Coverage Matrix

```json
{
  "detectionCoverage": {
    "techniques": [
      {
        "techniqueId": "T1189",
        "techniqueName": "Drive-by Compromise",
        "coverage": "full",
        "detectionMethods": ["Network monitoring", "Browser process monitoring"],
        "gaps": [],
        "lastValidated": "2026-04-28"
      }
    ],
    "summary": {
      "totalTechniques": 10,
      "fullCoverage": 7,
      "partialCoverage": 2,
      "noCoverage": 1,
      "coveragePercentage": 0.8
    }
  }
}
```

### Security Metrics

```json
{
  "metrics": {
    "mttd": {"value": 15, "unit": "minutes"},
    "mttr": {"value": 2, "unit": "hours"},
    "mttc": {"value": 30, "unit": "minutes"},
    "detectionRate": 0.95,
    "falsePositiveRate": 0.05,
    "alertVolume": {"daily": 150, "escalated": 10}
  }
}
```

## Supply Chain Security (v0.6.0)

### SBOM Reference

```json
{
  "sbom": {
    "format": "cyclonedx",
    "version": "1.5",
    "location": "./sbom.json",
    "generatedAt": "2026-04-28T10:00:00Z"
  }
}
```

### VEX Statements

```json
{
  "vexStatements": [
    {
      "vulnerability": "CVE-2024-12345",
      "product": "my-application",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "statement": "The vulnerable function is not called in our codebase"
    }
  ]
}
```

### Dependency Risks

```json
{
  "dependencyRisks": [
    {
      "component": "pkg:npm/lodash@4.17.20",
      "vulnerability": "CVE-2021-23337",
      "severity": "high",
      "fixedIn": "4.17.21",
      "remediation": "Upgrade to lodash@4.17.21"
    }
  ]
}
```

## SSVC Assessment (v0.6.0)

```json
{
  "ssvc": {
    "vulnerability": "CVE-2024-12345",
    "exploitation": "active",
    "automatable": "yes",
    "technicalImpact": "total",
    "missionPrevalence": "essential",
    "publicWellBeing": "material",
    "decision": "act",
    "assessedAt": "2026-04-28T10:00:00Z"
  }
}
```

Decision tree outputs:

| Decision | Description |
|----------|-------------|
| `track` | No action required, monitor only |
| `track_star` | Closer monitoring warranted |
| `attend` | Address within normal cycles |
| `act` | Immediate action required |

## Attack Path Analysis (v0.6.0)

Build attack graphs from threat models and analyze paths:

```go
// Build graph from diagram
graph := ir.BuildAttackGraphFromDiagram(diagramIR)

// Find all paths from entry to target
paths := graph.FindAllPaths("attacker", "database")

// Find shortest path
shortest := graph.FindShortestPath("attacker", "database")

// Find critical (highest risk) paths
critical := graph.FindCriticalPaths("attacker", "database", 3)

// Calculate path risk
risk := graph.CalculatePathRisk(path)

// Reachability analysis
reachable := graph.ReachabilityAnalysis("attacker")
```

## JSON Schemas

- [threat-model.schema.json](./threat-model.schema.json)
- [diagram.schema.json](./diagram.schema.json)

## Migration from v0.5.0

v0.6.0 is fully backward compatible with v0.5.0. All new fields are optional.

To take advantage of new features:

1. Add role-based guidance (`redTeam`, `blueTeam`, `remediation`)
2. Add FAIR risk assessment (`riskAssessment`)
3. Map attacks to OWASP ASI categories (`asiIds`)
4. Add purple team data (`atomicTests`, `detectionCoverage`, `metrics`)
5. Add supply chain data (`sbom`, `vexStatements`, `dependencyRisks`)
