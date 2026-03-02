# CVSS

CVSS (Common Vulnerability Scoring System) provides a standardized method for rating the severity of security vulnerabilities.

## Overview

CVSS scores range from 0.0 to 10.0:

| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

## CVSS v3.1 Metrics

### Base Metrics

| Metric | Values | Description |
|--------|--------|-------------|
| Attack Vector (AV) | N/A/L/P | Network/Adjacent/Local/Physical |
| Attack Complexity (AC) | L/H | Low/High |
| Privileges Required (PR) | N/L/H | None/Low/High |
| User Interaction (UI) | N/R | None/Required |
| Scope (S) | U/C | Unchanged/Changed |
| Confidentiality (C) | N/L/H | None/Low/High |
| Integrity (I) | N/L/H | None/Low/High |
| Availability (A) | N/L/H | None/Low/High |

## JSON Mapping Format

```json
{
  "mappings": {
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3,
      "severity": "Critical"
    }
  }
}
```

## Example Vectors

### Critical (9.3) - WebSocket Localhost Takeover

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
```

- **AV:N** - Network accessible (via malicious website)
- **AC:L** - Low complexity (simple exploit)
- **PR:N** - No privileges required
- **UI:R** - User must visit malicious page
- **S:C** - Scope changed (browser → agent)
- **C:H** - High confidentiality impact
- **I:H** - High integrity impact
- **A:N** - No availability impact

### High (7.5) - Authentication Bypass

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

### Medium (5.3) - Information Disclosure

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
```

## Calculating CVSS Scores

Use the NIST CVSS Calculator or include scores from CVE databases:

```json
{
  "mappings": {
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3
    },
    "cwe": [
      {"id": "CWE-346", "name": "Origin Validation Error"}
    ]
  }
}
```

## Complete Example

```json
{
  "type": "attack-chain",
  "title": "Critical Vulnerability Assessment",
  "mappings": {
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3,
      "severity": "Critical"
    },
    "cwe": [
      {"id": "CWE-346", "name": "Origin Validation Error"},
      {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts"}
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"}
    ]
  }
}
```

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [NIST CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
- [CVSS User Guide](https://www.first.org/cvss/user-guide)
