# Risk Assessment Guide

This guide explains how to use the structured risk assessment features in threat-model-spec.

## Overview

Risk assessment helps prioritize threats by evaluating:

- **Likelihood** — How probable is the threat?
- **Impact** — How severe are the consequences?
- **Risk Score** — Likelihood × Impact

## Risk Assessment Fields

Add a `risk` field to `ThreatEntry` or `Scenario`:

```json
{
  "risk": {
    "likelihood": 4,
    "impact": 5,
    "score": 20,
    "level": "critical",
    "likelihoodRationale": "Public API with history of similar vulnerabilities",
    "impactRationale": "Full database access including PII"
  }
}
```

## Likelihood Scale

| Score | Level | Description | Examples |
|-------|-------|-------------|----------|
| 1 | Rare | Requires exceptional circumstances | Zero-day + insider knowledge |
| 2 | Unlikely | Could occur but not expected | Complex multi-step attack |
| 3 | Possible | Reasonable chance | Known vulnerability pattern |
| 4 | Likely | Expected to occur | Exposed API, weak auth |
| 5 | Almost Certain | Will almost certainly occur | Public exploit available |

### Factors Affecting Likelihood

- **Attack Surface** — Is the target exposed?
- **Complexity** — How difficult is exploitation?
- **Skill Required** — Script kiddie vs nation-state?
- **Motivation** — Is there incentive to attack?
- **History** — Have similar attacks occurred?

## Impact Scale

| Score | Level | Description | Examples |
|-------|-------|-------------|----------|
| 1 | Negligible | Minimal business impact | Minor UI bug |
| 2 | Minor | Limited, easily recoverable | Temporary service degradation |
| 3 | Moderate | Noticeable, some effort to recover | Partial data exposure |
| 4 | Major | Significant, substantial effort | Breach of sensitive data |
| 5 | Severe | Critical, potentially unrecoverable | Full system compromise |

### Factors Affecting Impact

- **Confidentiality** — Data exposure severity
- **Integrity** — Data corruption potential
- **Availability** — Service disruption duration
- **Financial** — Direct and indirect costs
- **Reputation** — Brand and trust damage
- **Compliance** — Regulatory penalties

## Risk Matrix

Risk Score = Likelihood × Impact

```
Impact →
    │ 1    2    3    4    5
────┼─────────────────────────
L 5 │ 5    10   15   20   25
i 4 │ 4    8    12   16   20
k 3 │ 3    6    9    12   15
e 2 │ 2    4    6    8    10
  1 │ 1    2    3    4    5
```

## Risk Levels

| Score Range | Level | Color | Action Required |
|-------------|-------|-------|-----------------|
| 20-25 | Critical | Red | Immediate action, block release |
| 15-19 | High | Orange | Address before release |
| 8-14 | Medium | Yellow | Plan mitigation, track |
| 4-7 | Low | Blue | Monitor and review |
| 1-3 | Info | Gray | Document and accept |

## Usage Examples

### High-Risk Threat

```json
{
  "id": "threat-sql-injection",
  "title": "SQL Injection in Search API",
  "status": "potential",
  "risk": {
    "likelihood": 4,
    "impact": 5,
    "likelihoodRationale": "User input directly in query, no parameterization",
    "impactRationale": "Full database access, PII exposure, GDPR violation"
  }
}
```

Score: 4 × 5 = 20 → **Critical**

### Low-Risk Threat

```json
{
  "id": "threat-info-disclosure",
  "title": "Version Header Disclosure",
  "status": "potential",
  "risk": {
    "likelihood": 5,
    "impact": 1,
    "likelihoodRationale": "Header visible to all requests",
    "impactRationale": "Version info only, no direct exploit"
  }
}
```

Score: 5 × 1 = 5 → **Low**

### Scenario Risk Assessment

```json
{
  "id": "scenario-account-takeover",
  "title": "Account Takeover via Password Reset",
  "risk": {
    "likelihood": 3,
    "impact": 4,
    "likelihoodRationale": "Requires email access, but reset tokens are weak",
    "impactRationale": "Full account compromise, access to user data"
  },
  "businessImpact": "User trust damage, potential legal liability"
}
```

Score: 3 × 4 = 12 → **Medium**

## Best Practices

### 1. Be Consistent

Use the same criteria across all threats for comparable scores.

### 2. Document Rationale

Always explain why you chose specific likelihood/impact values:

```json
{
  "likelihoodRationale": "Specific reasoning here",
  "impactRationale": "Specific reasoning here"
}
```

### 3. Review with Stakeholders

- Security team validates likelihood estimates
- Business owners validate impact estimates
- Document disagreements and resolutions

### 4. Update Regularly

Risk assessments change as:

- New vulnerabilities are discovered
- Mitigations are implemented
- Business context changes
- Threat landscape evolves

### 5. Consider Attack Prerequisites

Factor in preconditions when assessing likelihood:

```json
{
  "preconditions": [
    "Attacker has network access",
    "Victim clicks malicious link",
    "Session token is not rotated"
  ]
}
```

## Integration with Threat Status

| Status | Typical Risk Focus |
|--------|-------------------|
| `potential` | Estimate based on design analysis |
| `theoretical` | Estimate based on STRIDE/LINDDUN |
| `identified` | Refine based on actual findings |
| `mitigated` | Residual risk assessment |

## Prioritization Workflow

1. **Identify threats** — Use STRIDE/LINDDUN systematically
2. **Assess risk** — Score each threat
3. **Sort by score** — Focus on critical/high first
4. **Plan mitigations** — Address highest risks
5. **Re-assess** — Update scores after mitigation
6. **Accept residual risk** — Document accepted risks

## Compliance Considerations

Different frameworks may require specific risk assessment approaches:

| Framework | Requirement |
|-----------|-------------|
| GDPR | Data protection impact assessment |
| PCI-DSS | Risk assessment for cardholder data |
| SOC 2 | Risk assessment process documentation |
| ISO 27001 | Information security risk assessment |
| NIST | Risk assessment per SP 800-30 |

Map your risk assessments to compliance requirements using the `complianceFrameworks` field on assets.
