# OpenClaw WebSocket Localhost Takeover

This example demonstrates how to use D2TM to visualize the OpenClaw vulnerability discovered by Oasis Security.

## Vulnerability Summary

**Severity:** High
**Fixed in:** v2026.2.25
**Reference:** [Oasis Security Blog](https://www.oasis.security/blog/openclaw-vulnerability)

OpenClaw, a popular open-source AI agent, was vulnerable to hijacking from any website due to a chain of security flaws in how it handled localhost WebSocket connections.

## Attack Chain

| Step | Action | Vulnerability Exploited |
|------|--------|------------------------|
| 1 | Victim visits malicious website | Social engineering / drive-by |
| 2 | Website loads malicious JavaScript | - |
| 3 | JS opens WebSocket to localhost:9999 | WebSocket bypasses same-origin policy |
| 4 | JS brute-forces gateway password | No rate limiting for localhost |
| 5 | JS registers as trusted device | Auto-approve pairing from localhost |
| 6-8 | Attacker controls AI agent | Full compromise |
| 9-10 | Data exfiltrated to attacker | Config, logs, API keys stolen |

## STRIDE Threat Analysis

| Threat | Description |
|--------|-------------|
| **Spoofing** | Browser JS appears as legitimate localhost connection |
| **Elevation of Privilege** | No rate limit + auto-approve grants admin access |
| **Information Disclosure** | Config, logs, and API keys exfiltrated |

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access (TA0001) | Trusted Relationship (T1199) | Localhost implicitly trusted |
| Credential Access (TA0006) | Brute Force | No rate limiting on auth |
| Exfiltration (TA0010) | Over C2 Channel | Data sent back via WebSocket |

## Rendering the Diagram

```bash
# Render to SVG
d2 attack_chain.d2 attack_chain.svg

# Render with specific layout engine
d2 --layout elk attack_chain.d2 attack_chain.svg

# Render to PNG
d2 --format png attack_chain.d2 attack_chain.png
```

## Key Security Lessons

1. **Never exempt localhost from rate limiting** — browsers execute untrusted code
2. **Require user confirmation for all device pairings** — even from loopback
3. **Use cryptographic tokens over passwords** — for local service auth
4. **Validate WebSocket Origin headers** — even for localhost
5. **Consider Unix sockets** — instead of TCP localhost for local IPC

## Files

- `attack_chain.d2` — D2 source diagram
- `attack_chain.svg` — Rendered SVG output
