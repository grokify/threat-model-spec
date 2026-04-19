# Design-Time Threat Modeling Guide

This guide explains how to use threat-model-spec for **proactive** threat modeling during the design phase of SDLC, before features are built.

## Overview

Traditional threat modeling often focuses on documenting known vulnerabilities and incidents. Design-time threat modeling takes a proactive approach:

- Identify potential threats before implementation
- Analyze attack scenarios before they happen
- Prioritize security investments based on risk
- Integrate threat modeling into design reviews

## When to Use Design-Time Threat Modeling

| Phase | Use Case |
|-------|----------|
| **Design** | New feature planning, architecture review |
| **Development** | Code review, PR security checks |
| **Review** | Security audit, penetration test planning |
| **Production** | Retrospective analysis (use `phase: production`) |
| **Incident** | Post-incident analysis (use `phase: incident`) |

## Setting the Model Phase

Use the `phase` field to indicate the SDLC stage:

```json
{
  "id": "auth-feature-design",
  "title": "Authentication Feature Threat Model",
  "phase": "design",
  "description": "Threat analysis for planned OAuth2 implementation"
}
```

Available phases: `design`, `development`, `review`, `production`, `incident`

## Threat Status for Design-Time Modeling

Use `potential` and `theoretical` statuses for hypothetical threats:

| Status | Use Case |
|--------|----------|
| `potential` | Threat identified during design review |
| `theoretical` | Threat derived from STRIDE/LINDDUN analysis |
| `identified` | Threat confirmed through testing or incident |

```json
{
  "threats": [
    {
      "id": "threat-1",
      "title": "OAuth Token Theft",
      "status": "potential",
      "description": "Attacker could steal OAuth tokens via XSS",
      "strideCategory": "I",
      "risk": {
        "likelihood": 3,
        "impact": 4
      }
    }
  ]
}
```

## Risk Assessment

Use structured risk scoring to prioritize threats:

```json
{
  "risk": {
    "likelihood": 4,
    "impact": 5,
    "likelihoodRationale": "Public API with known vulnerability pattern",
    "impactRationale": "Full access to user PII if exploited"
  }
}
```

### Likelihood Scale (1-5)

| Score | Level | Description |
|-------|-------|-------------|
| 1 | Rare | Requires exceptional circumstances |
| 2 | Unlikely | Could occur but not expected |
| 3 | Possible | Reasonable chance of occurrence |
| 4 | Likely | Expected to occur |
| 5 | Almost Certain | Will almost certainly occur |

### Impact Scale (1-5)

| Score | Level | Description |
|-------|-------|-------------|
| 1 | Negligible | Minimal business impact |
| 2 | Minor | Limited impact, easily recoverable |
| 3 | Moderate | Noticeable impact, some effort to recover |
| 4 | Major | Significant impact, substantial effort to recover |
| 5 | Severe | Critical impact, may be unrecoverable |

### Risk Levels

Risk Score = Likelihood × Impact (1-25)

| Score | Level | Action |
|-------|-------|--------|
| 20-25 | Critical | Immediate action required |
| 15-19 | High | Address before release |
| 8-14 | Medium | Plan mitigation |
| 4-7 | Low | Monitor and review |
| 1-3 | Info | Accept or document |

## Asset Inventory

Document assets being protected to understand impact:

```json
{
  "assets": [
    {
      "id": "asset-userdb",
      "name": "User Database",
      "type": "data",
      "classification": "restricted",
      "dataTypes": ["PII", "credentials"],
      "complianceFrameworks": ["GDPR", "SOC2"],
      "elementIds": ["db-users"]
    }
  ]
}
```

### Sensitivity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| `public` | Publicly available | Marketing content, public docs |
| `internal` | Internal use only | Internal wikis, team data |
| `confidential` | Business confidential | Strategy docs, financial data |
| `restricted` | Highly restricted | PII, PHI, credentials |
| `secret` | Secret/classified | Encryption keys, classified data |

## Scenario Analysis

Model what-if attack scenarios:

```json
{
  "scenarios": [
    {
      "id": "scenario-1",
      "title": "External Attacker Compromises API",
      "type": "external-attack",
      "threatActorId": "actor-external",
      "preconditions": [
        "Attacker has network access to public API",
        "API has authentication bypass vulnerability"
      ],
      "attackPath": [
        "Reconnaissance of public API endpoints",
        "Identify authentication weakness",
        "Craft malicious request to bypass auth",
        "Access user database"
      ],
      "targetAssetIds": ["asset-userdb"],
      "risk": {
        "likelihood": 4,
        "impact": 5
      },
      "outcome": "Unauthorized access to user PII",
      "businessImpact": "GDPR fines, reputation damage, customer churn"
    }
  ]
}
```

## Network Topology Mapping

Map planned architecture to network details:

```json
{
  "elements": [
    {
      "id": "api-server",
      "label": "API Server",
      "type": "process",
      "network": {
        "host": "api.example.com",
        "ports": [443],
        "protocols": ["HTTPS", "gRPC"],
        "zone": "dmz",
        "cloud": {
          "provider": "aws",
          "region": "us-east-1",
          "vpc": "vpc-production"
        }
      }
    }
  ]
}
```

## Workflow: Design-Time Threat Modeling

### Step 1: Create Architecture Diagram (DFD)

Start with a Data Flow Diagram of the planned feature:

```json
{
  "id": "feature-oauth",
  "title": "OAuth2 Implementation",
  "phase": "design",
  "diagrams": [
    {
      "type": "dfd",
      "title": "OAuth2 Data Flow",
      "elements": [...],
      "boundaries": [...],
      "flows": [...]
    }
  ]
}
```

### Step 2: Apply STRIDE/LINDDUN

For each element and flow, systematically apply threat categories:

```json
{
  "threats": [
    {
      "id": "threat-s1",
      "title": "Token Spoofing",
      "status": "theoretical",
      "strideCategory": "S",
      "affectedElements": ["oauth-tokens"],
      "risk": {"likelihood": 3, "impact": 4}
    },
    {
      "id": "threat-i1",
      "title": "Token Identifiability",
      "status": "theoretical",
      "linddunCategory": "I",
      "affectedElements": ["oauth-tokens"],
      "risk": {"likelihood": 2, "impact": 3}
    }
  ]
}
```

### Step 3: Identify Assets at Risk

Document what's being protected:

```json
{
  "assets": [
    {
      "id": "asset-tokens",
      "name": "OAuth Tokens",
      "type": "credential",
      "classification": "restricted"
    }
  ]
}
```

### Step 4: Model Attack Scenarios

Create what-if scenarios for high-risk threats:

```json
{
  "scenarios": [
    {
      "id": "scenario-token-theft",
      "title": "OAuth Token Theft via XSS",
      "preconditions": ["XSS vulnerability exists", "Tokens stored in localStorage"],
      "attackPath": ["Inject malicious script", "Steal tokens", "Impersonate user"]
    }
  ]
}
```

### Step 5: Plan Mitigations

Document planned countermeasures:

```json
{
  "mitigations": [
    {
      "id": "mit-httponly",
      "title": "Use HttpOnly Cookies",
      "status": "planned",
      "threatIds": ["threat-s1"],
      "owner": "auth-team"
    }
  ]
}
```

### Step 6: Use Attack Trees for Complex Threats

For critical threats, decompose with attack trees:

```json
{
  "diagrams": [
    {
      "type": "attack-tree",
      "title": "Account Takeover Paths",
      "attackTree": {
        "goal": "Take over user account",
        "root": {
          "id": "root",
          "label": "Account Takeover",
          "gate": "OR",
          "children": [
            {"id": "steal-creds", "label": "Steal Credentials"},
            {"id": "bypass-auth", "label": "Bypass Authentication"}
          ]
        }
      }
    }
  ]
}
```

## Integration with SDLC

### Design Review Checklist

1. Create threat model JSON file
2. Set `phase: design`
3. Document all components in DFD
4. Apply STRIDE to each element
5. Assess risk for each threat
6. Plan mitigations for high/critical risks
7. Review with security team

### CI/CD Integration

Validate threat models in CI:

```bash
# Validate threat model schema
tms validate threat-model.json

# Check for unmitigated critical risks
tms validate --strict threat-model.json
```

### PR Review

Include threat model updates in PRs that introduce:

- New external APIs
- Authentication/authorization changes
- Data storage changes
- New trust boundaries

## Example: Complete Design-Time Threat Model

```json
{
  "id": "feature-user-export",
  "title": "User Data Export Feature",
  "phase": "design",
  "version": "0.1.0",
  "description": "Threat model for planned GDPR data export feature",
  "authors": [{"name": "Security Team"}],
  "assets": [
    {
      "id": "asset-export",
      "name": "User Export Data",
      "type": "data",
      "classification": "restricted",
      "dataTypes": ["PII"],
      "complianceFrameworks": ["GDPR"]
    }
  ],
  "diagrams": [
    {
      "type": "dfd",
      "title": "Data Export Flow",
      "elements": [
        {"id": "user", "label": "User", "type": "external-entity"},
        {"id": "api", "label": "Export API", "type": "api"},
        {"id": "queue", "label": "Job Queue", "type": "process"},
        {"id": "storage", "label": "Export Storage", "type": "datastore"}
      ],
      "flows": [
        {"from": "user", "to": "api", "label": "Request export"},
        {"from": "api", "to": "queue", "label": "Queue job"},
        {"from": "queue", "to": "storage", "label": "Generate export"}
      ],
      "threats": [
        {
          "id": "threat-1",
          "title": "Unauthorized Export Request",
          "status": "potential",
          "strideCategory": "S",
          "affectedElements": ["api"],
          "risk": {"likelihood": 3, "impact": 5},
          "attackVector": "Attacker requests export for another user"
        }
      ],
      "mitigations": [
        {
          "id": "mit-1",
          "title": "Verify User Identity",
          "status": "planned",
          "threatIds": ["threat-1"]
        }
      ]
    }
  ],
  "scenarios": [
    {
      "id": "scenario-1",
      "title": "IDOR Attack on Export",
      "type": "data-breach",
      "preconditions": ["Export ID is predictable", "No ownership check"],
      "outcome": "Attacker downloads another user's data"
    }
  ]
}
```

## References

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Microsoft SDL Threat Modeling](https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling)
- [STRIDE Threat Model](concepts/frameworks/stride.md)
- [LINDDUN Privacy Framework](concepts/frameworks/linddun.md)
