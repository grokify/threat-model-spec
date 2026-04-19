# Threat Model Specification v0.4.0

This document describes the Threat Model Specification format, a JSON-based intermediate representation for security threat modeling diagrams.

## Overview

A threat model is defined in a single JSON file containing:

- **Metadata**: Title, description, version, authors
- **Mappings**: Security framework references (MITRE ATT&CK, OWASP, STRIDE, etc.)
- **Diagrams**: Multiple diagram views (DFD, Attack Chain, Sequence, Attack Tree)
- **Security Lifecycle**: Threat actors, mitigations, detections, response actions

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
| `authors` | array | List of Author objects |
| `references` | array | External references |
| `mappings` | object | Shared framework mappings (inherited by diagrams) |
| `threatActors` | array | Adversary profiles |
| `assumptions` | array | Security assumptions |
| `prerequisites` | array | Attack prerequisites |
| `mitigations` | array | Shared mitigations (inherited by diagrams) |

## DiagramView / DiagramIR

Represents a single diagram view within a threat model.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | enum | Diagram type: `dfd`, `attack-chain`, `sequence`, `attack-tree` |
| `title` | string | Diagram title (DiagramIR only) |

### Common Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Diagram description |
| `direction` | enum | Layout direction: `right`, `down`, `left`, `up` |
| `legend` | object | Legend display options |
| `mappings` | object | Diagram-specific mappings (overrides parent) |

### DFD Fields

| Field | Type | Description |
|-------|------|-------------|
| `elements` | array | Processes, datastores, external entities |
| `boundaries` | array | Trust boundaries |
| `flows` | array | Data flows between elements |

### Attack Chain Fields

| Field | Type | Description |
|-------|------|-------------|
| `elements` | array | Attack chain elements |
| `attacks` | array | Attack steps with MITRE mappings |
| `targets` | array | High-value target assets |

### Sequence Diagram Fields

| Field | Type | Description |
|-------|------|-------------|
| `actors` | array | Sequence diagram lifelines |
| `phases` | array | Attack phases grouping messages |
| `messages` | array | Messages between actors |

### Attack Tree Fields

| Field | Type | Description |
|-------|------|-------------|
| `attackTree` | object | Attack tree with root and nodes |

### Security Lifecycle Fields

| Field | Type | Description |
|-------|------|-------------|
| `threats` | array | Identified threats with status |
| `mitigations` | array | Countermeasures |
| `detections` | array | Detection capabilities |
| `responseActions` | array | Incident response actions |

## Diagram Types

### DFD (Data Flow Diagram)

Shows data flows between system components with trust boundaries.

```json
{
  "type": "dfd",
  "title": "System Data Flow",
  "elements": [
    {"id": "user", "label": "User", "type": "external-entity"},
    {"id": "api", "label": "API Server", "type": "process"},
    {"id": "db", "label": "Database", "type": "datastore"}
  ],
  "boundaries": [
    {"id": "dmz", "label": "DMZ", "type": "network"}
  ],
  "flows": [
    {"from": "user", "to": "api", "label": "HTTPS Request"},
    {"from": "api", "to": "db", "label": "SQL Query"}
  ]
}
```

### Attack Chain

Shows attack progression with MITRE ATT&CK mappings.

```json
{
  "type": "attack-chain",
  "title": "Credential Theft Attack",
  "elements": [
    {"id": "attacker", "label": "Attacker", "type": "external-entity"},
    {"id": "victim", "label": "Victim Workstation", "type": "process"}
  ],
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "victim",
      "label": "Phishing Email",
      "mitreTactic": "TA0001",
      "mitreTechnique": "T1566"
    }
  ]
}
```

### Sequence Diagram

Shows time-ordered attack interactions.

```json
{
  "type": "sequence",
  "title": "Authentication Bypass",
  "actors": [
    {"id": "attacker", "label": "Attacker", "malicious": true},
    {"id": "server", "label": "Server"}
  ],
  "messages": [
    {"seq": 1, "from": "attacker", "to": "server", "label": "Malformed Token"}
  ],
  "phases": [
    {"name": "Initial Access", "mitreTactic": "TA0001", "startMessage": 1, "endMessage": 1}
  ]
}
```

### Attack Tree

Hierarchical decomposition of attack goals with AND/OR logic.

```json
{
  "type": "attack-tree",
  "title": "Data Exfiltration",
  "attackTree": {
    "rootId": "goal",
    "nodes": [
      {"id": "goal", "label": "Exfiltrate Data", "nodeType": "OR", "children": ["path1", "path2"]},
      {"id": "path1", "label": "SQL Injection", "nodeType": "LEAF", "mitreTechnique": "T1190"},
      {"id": "path2", "label": "Insider Threat", "nodeType": "LEAF"}
    ]
  }
}
```

## Element Types

| Type | Description | D2 Shape |
|------|-------------|----------|
| `process` | Processing component | Rectangle |
| `datastore` | Data storage | Cylinder |
| `external-entity` | External actor/system | Rectangle (dashed) |
| `gateway` | API gateway | Hexagon |
| `browser` | Web browser | Rectangle |
| `agent` | Software agent | Rectangle |
| `api` | API endpoint | Rectangle |

## Boundary Types

| Type | Description | Color |
|------|-------------|-------|
| `browser` | Browser sandbox | Blue |
| `localhost` | Localhost trust | Purple |
| `network` | Network zone | Green |
| `cloud` | Cloud environment | Light blue |
| `breached` | Compromised boundary | Dark red |

## Framework Mappings

### Threat Frameworks

| Framework | Field | Required Fields |
|-----------|-------|-----------------|
| MITRE ATT&CK | `mitreAttack` | `tacticId`, `techniqueId` |
| MITRE ATLAS | `mitreAtlas` | `tacticId`, `techniqueId` |
| OWASP | `owasp` | `category`, `id` |
| STRIDE | `stride` | `category` |
| LINDDUN | `linddun` | `category` |
| CWE | `cwe` | `id` |
| CVE | `cve` | `id` |
| CVSS | `cvss` | `version`, `vector`, `baseScore`, `severity` |

### Control Frameworks

| Framework | Field | Required Fields |
|-----------|-------|-----------------|
| NIST CSF | `controls.nistCsf` | `function`, `category` |
| CIS Controls v8 | `controls.cis` | `controlId` |
| ISO 27001 | `controls.iso27001` | `controlId` |

### Compliance Frameworks

| Framework | Value |
|-----------|-------|
| SOC 2 | `soc2` |
| PCI-DSS | `pci-dss` |
| HIPAA | `hipaa` |
| GDPR | `gdpr` |
| CCPA | `ccpa` |
| FedRAMP | `fedramp` |
| NIST SP 800-53 | `nist-sp-800-53` |
| NIST SP 800-171 | `nist-sp-800-171` |
| SOX | `sox` |
| GLBA | `glba` |

## STRIDE Threats

| Code | Name | Description |
|------|------|-------------|
| `S` | Spoofing | Identity spoofing |
| `T` | Tampering | Data tampering |
| `R` | Repudiation | Non-repudiation failures |
| `I` | Information Disclosure | Information leakage |
| `D` | Denial of Service | Availability attacks |
| `E` | Elevation of Privilege | Privilege escalation |

## LINDDUN Privacy Threats

| Code | Name | Description |
|------|------|-------------|
| `L` | Linkability | Linking items of interest |
| `I` | Identifiability | Identifying data subjects |
| `N` | Non-repudiation | Unable to deny actions |
| `D` | Detectability | Detecting item existence |
| `Di` | Disclosure | Information disclosure |
| `U` | Unawareness | Lack of awareness |
| `Nc` | Non-compliance | Regulatory non-compliance |

## Security Lifecycle

### Threat Status

| Status | Description |
|--------|-------------|
| `identified` | Threat has been identified |
| `analyzing` | Under analysis |
| `mitigated` | Mitigation implemented |
| `accepted` | Risk accepted |
| `transferred` | Risk transferred |
| `monitoring` | Being monitored |

### Mitigation Status

| Status | Description |
|--------|-------------|
| `planned` | Planned for implementation |
| `implemented` | Fully implemented |
| `partial` | Partially implemented |
| `accepted` | Risk accepted without mitigation |
| `transferred` | Risk transferred to third party |
| `not-applicable` | Not applicable |

### Detection Coverage

| Coverage | Description |
|----------|-------------|
| `none` | No detection capability |
| `partial` | Partial detection |
| `full` | Full detection coverage |

## Attack Tree Node Types

| Type | Description |
|------|-------------|
| `AND` | All children must succeed |
| `OR` | Any child can succeed |
| `LEAF` | Terminal node (actual attack) |

## Threat Actor Types

| Type | Description |
|------|-------------|
| `nation-state` | Nation-state actor |
| `criminal` | Criminal organization |
| `hacktivist` | Hacktivist group |
| `insider` | Malicious insider |
| `competitor` | Business competitor |
| `terrorist` | Terrorist organization |
| `script-kiddie` | Unskilled attacker |
| `researcher` | Security researcher |

## Sophistication Levels

| Level | Description |
|-------|-------------|
| `none` | No technical capability |
| `low` | Basic skills |
| `medium` | Moderate expertise |
| `high` | Advanced capabilities |
| `advanced` | Nation-state level |

## Schema URLs

- **ThreatModel**: `https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/threat-model.schema.json`
- **DiagramIR**: `https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/diagram.schema.json`

## Example

```json
{
  "$schema": "https://github.com/grokify/threat-model-spec/docs/versions/v0.4.0/threat-model.schema.json",
  "id": "webapp-threat-model",
  "title": "Web Application Threat Model",
  "version": "1.0.0",
  "mappings": {
    "mitreAttack": [
      {"tacticId": "TA0001", "techniqueId": "T1190", "techniqueName": "Exploit Public-Facing Application"}
    ],
    "owasp": [
      {"category": "web", "id": "A03:2021", "name": "Injection"}
    ]
  },
  "mitigations": [
    {
      "id": "mit-1",
      "title": "Input Validation",
      "status": "implemented",
      "owner": "security-team"
    }
  ],
  "diagrams": [
    {
      "type": "dfd",
      "title": "Application Data Flow",
      "elements": [
        {"id": "user", "label": "User", "type": "external-entity"},
        {"id": "webapp", "label": "Web App", "type": "process"}
      ],
      "flows": [
        {"from": "user", "to": "webapp", "label": "HTTP Request"}
      ]
    }
  ]
}
```

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [LINDDUN](https://linddun.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
