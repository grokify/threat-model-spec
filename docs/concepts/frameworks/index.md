# Security Frameworks

Threat Model Spec supports mapping threats to industry-standard security frameworks for comprehensive documentation and compliance.

## Supported Frameworks

| Framework | Purpose | Example |
|-----------|---------|---------|
| [STRIDE](stride.md) | Threat categorization | Spoofing, Tampering, etc. |
| [MITRE ATT&CK](mitre-attack.md) | Adversary tactics/techniques | T1189 Drive-by Compromise |
| [MITRE ATLAS](mitre-atlas.md) | AI/ML threats | AML.T0024 Prompt Injection |
| [OWASP](owasp.md) | Web/API/LLM vulnerabilities | API2:2023 Broken Authentication |
| [CWE](cwe.md) | Weakness enumeration | CWE-346 Origin Validation Error |
| [CVSS](cvss.md) | Severity scoring | CVSS:3.1/AV:N/AC:L/... |

## Using Framework Mappings

Add mappings to your threat model JSON in the `mappings` field:

```json
{
  "type": "attack-chain",
  "title": "WebSocket Attack",
  "mappings": {
    "mitreAttack": [
      {
        "tacticId": "TA0001",
        "tacticName": "Initial Access",
        "techniqueId": "T1189",
        "techniqueName": "Drive-by Compromise"
      }
    ],
    "owasp": [
      {
        "category": "api",
        "id": "API2:2023",
        "name": "Broken Authentication"
      }
    ],
    "stride": [
      {
        "category": "S",
        "name": "Spoofing",
        "description": "Attacker impersonates legitimate client"
      }
    ],
    "cwe": [
      {
        "id": "CWE-346",
        "name": "Origin Validation Error"
      }
    ],
    "cvss": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
      "score": 9.3
    }
  }
}
```

## STIX 2.1 Export

Framework mappings are preserved when exporting to STIX 2.1:

```bash
tms generate model.json --stix -o model.stix.json
```

The STIX bundle includes:

- **Attack Patterns** with MITRE ATT&CK external references
- **Vulnerabilities** with CWE mappings
- **Threat Actors** for malicious elements
- **Indicators** for attack targets

## When to Use Each Framework

| Scenario | Recommended Frameworks |
|----------|----------------------|
| Web application security | OWASP Web Top 10, CWE |
| API security | OWASP API Top 10, CWE |
| AI/ML systems | MITRE ATLAS, OWASP LLM Top 10 |
| Incident response | MITRE ATT&CK, STRIDE |
| Compliance reporting | CVSS, CWE |
| Threat modeling workshops | STRIDE |
