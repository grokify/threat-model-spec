# OWASP Top 10

OWASP provides top 10 security risk lists for web applications, APIs, and LLM applications.

## Supported Categories

| Category | Full Name | Use Case |
|----------|-----------|----------|
| `web` | OWASP Top 10 | Traditional web applications |
| `api` | OWASP API Security Top 10 | REST/GraphQL APIs |
| `llm` | OWASP LLM Top 10 | Large Language Model applications |

## OWASP API Security Top 10 (2023)

| ID | Name | Description |
|----|------|-------------|
| API1:2023 | Broken Object Level Authorization | Accessing objects without proper auth |
| API2:2023 | Broken Authentication | Flaws in authentication mechanisms |
| API3:2023 | Broken Object Property Level Authorization | Exposing/modifying object properties |
| API4:2023 | Unrestricted Resource Consumption | No rate limiting or quotas |
| API5:2023 | Broken Function Level Authorization | Access to admin functions |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Abuse of business logic |
| API7:2023 | Server Side Request Forgery | SSRF vulnerabilities |
| API8:2023 | Security Misconfiguration | Insecure default configurations |
| API9:2023 | Improper Inventory Management | Unknown API endpoints |
| API10:2023 | Unsafe Consumption of APIs | Trusting third-party APIs |

## OWASP LLM Top 10 (2023)

| ID | Name | Description |
|----|------|-------------|
| LLM01:2023 | Prompt Injection | Manipulating LLM via crafted prompts |
| LLM02:2023 | Insecure Output Handling | Trusting LLM output without validation |
| LLM03:2023 | Training Data Poisoning | Corrupted training data |
| LLM04:2023 | Model Denial of Service | Resource exhaustion attacks |
| LLM05:2023 | Supply Chain Vulnerabilities | Compromised models/plugins |
| LLM06:2023 | Sensitive Information Disclosure | Leaking sensitive data |
| LLM07:2023 | Insecure Plugin Design | Vulnerable extensions |
| LLM08:2023 | Excessive Agency | Over-permissioned agents |
| LLM09:2023 | Overreliance | Blind trust in LLM output |
| LLM10:2023 | Model Theft | Stealing proprietary models |

## JSON Mapping Format

```json
{
  "mappings": {
    "owasp": [
      {
        "category": "api",
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": "No rate limiting allows brute force attacks",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
      },
      {
        "category": "llm",
        "id": "LLM01:2023",
        "name": "Prompt Injection",
        "description": "Malicious prompts control agent behavior"
      }
    ]
  }
}
```

## Example: API Security

```json
{
  "type": "attack-chain",
  "title": "API Authentication Bypass",
  "mappings": {
    "owasp": [
      {"category": "api", "id": "API2:2023", "name": "Broken Authentication"},
      {"category": "api", "id": "API4:2023", "name": "Unrestricted Resource Consumption"}
    ],
    "cwe": [
      {"id": "CWE-307", "name": "Improper Restriction of Excessive Authentication Attempts"}
    ]
  }
}
```

## Example: LLM Security

```json
{
  "type": "attack-chain",
  "title": "AI Agent Compromise",
  "mappings": {
    "owasp": [
      {"category": "llm", "id": "LLM01:2023", "name": "Prompt Injection"},
      {"category": "llm", "id": "LLM08:2023", "name": "Excessive Agency"}
    ],
    "mitreAtlas": [
      {"techniqueId": "AML.T0024", "techniqueName": "Prompt Injection"}
    ]
  }
}
```

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
