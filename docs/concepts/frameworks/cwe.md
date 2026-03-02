# CWE

CWE (Common Weakness Enumeration) is a community-developed list of software and hardware weakness types.

## Overview

CWE provides a common language for describing security weaknesses in architecture, design, code, or documentation.

## Common Weaknesses

| ID | Name | Category |
|----|------|----------|
| CWE-79 | Cross-site Scripting (XSS) | Injection |
| CWE-89 | SQL Injection | Injection |
| CWE-119 | Buffer Overflow | Memory |
| CWE-200 | Exposure of Sensitive Information | Information |
| CWE-269 | Improper Privilege Management | Access Control |
| CWE-284 | Improper Access Control | Access Control |
| CWE-306 | Missing Authentication | Authentication |
| CWE-307 | Improper Restriction of Excessive Auth Attempts | Authentication |
| CWE-346 | Origin Validation Error | Input Validation |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Session |
| CWE-400 | Uncontrolled Resource Consumption | Resource |
| CWE-502 | Deserialization of Untrusted Data | Injection |
| CWE-798 | Use of Hard-coded Credentials | Credentials |
| CWE-862 | Missing Authorization | Access Control |
| CWE-918 | Server-Side Request Forgery (SSRF) | Injection |

## JSON Mapping Format

```json
{
  "mappings": {
    "cwe": [
      {
        "id": "CWE-346",
        "name": "Origin Validation Error",
        "description": "WebSocket server accepts connections from any origin",
        "url": "https://cwe.mitre.org/data/definitions/346.html"
      },
      {
        "id": "CWE-307",
        "name": "Improper Restriction of Excessive Authentication Attempts",
        "description": "No rate limiting on password attempts"
      }
    ]
  }
}
```

## Relating CWE to Other Frameworks

CWE weaknesses often map to OWASP and STRIDE categories:

| CWE | OWASP | STRIDE |
|-----|-------|--------|
| CWE-89 (SQLi) | API8:2023 | Tampering |
| CWE-79 (XSS) | A03:2021 | Information Disclosure |
| CWE-306 (No Auth) | API2:2023 | Spoofing |
| CWE-307 (No Rate Limit) | API4:2023 | Denial of Service |
| CWE-346 (Origin) | API2:2023 | Spoofing |
| CWE-862 (No AuthZ) | API1:2023 | Elevation of Privilege |

## Example: Combined Mapping

```json
{
  "mappings": {
    "cwe": [
      {"id": "CWE-346", "name": "Origin Validation Error"}
    ],
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"}
    ],
    "stride": [
      {"category": "S", "name": "Spoofing"}
    ]
  }
}
```

## STIX 2.1 Export

CWE mappings are exported as Vulnerability objects:

```json
{
  "type": "vulnerability",
  "spec_version": "2.1",
  "name": "Origin Validation Error",
  "description": "WebSocket server accepts connections from any origin",
  "external_references": [
    {
      "source_name": "cwe",
      "external_id": "CWE-346",
      "url": "https://cwe.mitre.org/data/definitions/346.html"
    }
  ]
}
```

## References

- [CWE List](https://cwe.mitre.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CWE/SANS Top 25](https://www.sans.org/top25-software-errors/)
