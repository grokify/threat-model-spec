# OWASP Top 10

OWASP provides top 10 security risk lists for web applications, APIs, LLM applications, and agentic AI systems.

## Supported Categories

| Category | Value | Year | Use Case |
|----------|-------|------|----------|
| Web Applications | `web` | 2021 | Traditional web applications |
| API Security | `api` | 2023 | REST/GraphQL APIs |
| LLM Applications | `llm` | 2025 | Large Language Model applications |
| Agentic Applications | `agentic` | 2026 | Autonomous AI agents (ASI) |

## OWASP Web Top 10 (2021)

| ID | Name | Description |
|----|------|-------------|
| A01:2021 | Broken Access Control | Access control not properly enforced |
| A02:2021 | Cryptographic Failures | Failures related to cryptography |
| A03:2021 | Injection | SQL, NoSQL, OS command injection |
| A04:2021 | Insecure Design | Missing or ineffective security controls |
| A05:2021 | Security Misconfiguration | Improper security settings |
| A06:2021 | Vulnerable Components | Using vulnerable libraries/frameworks |
| A07:2021 | Auth Failures | Authentication and session management |
| A08:2021 | Software and Data Integrity | Code/data integrity violations |
| A09:2021 | Logging and Monitoring | Insufficient logging and monitoring |
| A10:2021 | SSRF | Server-Side Request Forgery |

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

## OWASP LLM Top 10 (2025)

| ID | Name | Description |
|----|------|-------------|
| LLM01:2025 | Prompt Injection | Manipulating LLM via crafted prompts |
| LLM02:2025 | Sensitive Information Disclosure | Leaking sensitive data in responses |
| LLM03:2025 | Supply Chain Vulnerabilities | Compromised models, plugins, or data |
| LLM04:2025 | Data and Model Poisoning | Corrupted training or fine-tuning data |
| LLM05:2025 | Improper Output Handling | Trusting LLM output without validation |
| LLM06:2025 | Excessive Agency | Over-permissioned autonomous actions |
| LLM07:2025 | System Prompt Leakage | Exposing system prompts |
| LLM08:2025 | Vector and Embedding Weaknesses | RAG and embedding vulnerabilities |
| LLM09:2025 | Misinformation | Generating false or misleading content |
| LLM10:2025 | Unbounded Consumption | Resource exhaustion attacks |

## OWASP Agentic Top 10 (ASI 2026)

The Agentic Security Initiative (ASI) addresses risks specific to autonomous AI agents.

| ID | Name | Description |
|----|------|-------------|
| ASI01:2026 | Agentic Prompt Injection | Injected instructions via various input channels |
| ASI02:2026 | Tool Misuse & Exploitation | Exploiting agent's access to tools |
| ASI03:2026 | Agent Identity & Privilege Abuse | Impersonation and privilege escalation |
| ASI04:2026 | Agentic Supply Chain Compromise | Compromised agent components or dependencies |
| ASI05:2026 | Unexpected Code Execution | Unintended code execution through agent |
| ASI06:2026 | Sensitive Data Exposure via Agents | Data leakage through agent actions |
| ASI07:2026 | Agent Goal & Instruction Manipulation | Altering agent objectives or instructions |
| ASI08:2026 | Agent Memory & Context Manipulation | Tampering with agent memory or context |
| ASI09:2026 | Human-Agent Trust Exploitation | Exploiting trust between users and agents |
| ASI10:2026 | Cascading Agent Failures | Propagating failures across agent systems |

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
        "id": "LLM01:2025",
        "name": "Prompt Injection",
        "description": "Malicious prompts control agent behavior"
      },
      {
        "category": "agentic",
        "id": "ASI02:2026",
        "name": "Tool Misuse & Exploitation",
        "description": "Attackers exploit agent's access to tools"
      }
    ]
  }
}
```

## Attack Step OWASP Mappings

Attack steps can include `owaspIds` and `asiIds` for framework mappings:

```json
{
  "attacks": [
    {
      "step": 6,
      "from": "gateway",
      "to": "agent",
      "label": "Access AI agent",
      "owaspIds": ["API8:2023", "LLM06:2025"],
      "asiIds": ["ASI02:2026", "ASI03:2026"]
    }
  ]
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
      {"category": "llm", "id": "LLM01:2025", "name": "Prompt Injection"},
      {"category": "llm", "id": "LLM06:2025", "name": "Excessive Agency"}
    ],
    "mitreAtlas": [
      {"techniqueId": "AML.T0024", "techniqueName": "Prompt Injection"}
    ]
  }
}
```

## Example: Agentic Security

```json
{
  "type": "attack-chain",
  "title": "AI Coding Agent Exploitation",
  "mappings": {
    "owasp": [
      {"category": "agentic", "id": "ASI02:2026", "name": "Tool Misuse & Exploitation"},
      {"category": "agentic", "id": "ASI05:2026", "name": "Unexpected Code Execution"},
      {"category": "llm", "id": "LLM01:2025", "name": "Prompt Injection"}
    ]
  },
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "repository",
      "label": "Plant malicious code comment",
      "asiIds": ["ASI01:2026"]
    },
    {
      "step": 2,
      "from": "repository",
      "to": "agent",
      "label": "Agent reads malicious context",
      "asiIds": ["ASI08:2026"]
    },
    {
      "step": 3,
      "from": "agent",
      "to": "system",
      "label": "Agent executes unauthorized commands",
      "asiIds": ["ASI02:2026", "ASI05:2026"]
    }
  ]
}
```

## Validation

Use `ValidateOWASPMappings()` to check OWASP IDs:

```go
warnings := diagramIR.ValidateOWASPMappings()
for _, w := range warnings {
    log.Printf("Warning: %s", w)
}
```

Use `GetOWASPEntry()` and `ValidateOWASPID()` for reference data:

```go
entry := ir.GetOWASPEntry("ASI02:2026")
if entry != nil {
    fmt.Printf("Name: %s\nDescription: %s\n", entry.Name, entry.Description)
}

if ir.ValidateOWASPID("API1:2023") {
    fmt.Println("Valid OWASP ID")
}
```

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)
- [OWASP Agentic Top 10 (ASI)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
