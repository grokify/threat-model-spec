# MITRE ATT&CK

MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations.

## Tactics Overview

Tactics represent the "why" of an attack — the adversary's tactical goal.

| ID | Tactic | Description |
|----|--------|-------------|
| TA0043 | Reconnaissance | Gathering information to plan operations |
| TA0042 | Resource Development | Establishing resources for operations |
| TA0001 | Initial Access | Getting into the network |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining foothold |
| TA0004 | Privilege Escalation | Gaining higher-level permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Understanding the environment |
| TA0008 | Lateral Movement | Moving through the environment |
| TA0009 | Collection | Gathering data of interest |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Manipulating or destroying systems |

## Common Techniques

| ID | Name | Tactic |
|----|------|--------|
| T1189 | Drive-by Compromise | Initial Access |
| T1199 | Trusted Relationship | Initial Access |
| T1078 | Valid Accounts | Initial Access |
| T1110 | Brute Force | Credential Access |
| T1059 | Command and Scripting Interpreter | Execution |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1082 | System Information Discovery | Discovery |
| T1557 | Adversary-in-the-Middle | Credential Access |

## JSON Mapping Format

```json
{
  "mappings": {
    "mitreAttack": [
      {
        "tacticId": "TA0001",
        "tacticName": "Initial Access",
        "techniqueId": "T1189",
        "techniqueName": "Drive-by Compromise",
        "description": "Malicious website serves exploit to victim browser",
        "url": "https://attack.mitre.org/techniques/T1189"
      },
      {
        "tacticId": "TA0006",
        "tacticName": "Credential Access",
        "techniqueId": "T1110",
        "techniqueName": "Brute Force",
        "description": "Password brute forcing without rate limiting"
      }
    ]
  }
}
```

## Attack Step Mapping

Map individual attack steps to techniques:

```json
{
  "attacks": [
    {
      "step": 1,
      "from": "attacker",
      "to": "browser",
      "label": "Serve malicious page",
      "mitreTechnique": "T1189"
    },
    {
      "step": 2,
      "from": "browser",
      "to": "agent",
      "label": "WebSocket connection",
      "mitreTechnique": "T1557"
    }
  ]
}
```

## Go Package

```go
import "github.com/grokify/threat-model-spec/killchain"

// Get all tactics
for _, tactic := range killchain.AllMITRETactics() {
    fmt.Printf("%s: %s\n", tactic.ID(), tactic.String())
    fmt.Printf("  URL: %s\n", tactic.URL())
}

// Use common techniques
tech := killchain.CommonTechniques["T1189"]
fmt.Printf("%s: %s (%s)\n", tech.ID, tech.Name, tech.Tactic.String())
```

## STIX 2.1 Export

MITRE ATT&CK mappings are exported as Attack Patterns with external references:

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "name": "Drive-by Compromise",
  "external_references": [
    {
      "source_name": "mitre-attack",
      "external_id": "T1189",
      "url": "https://attack.mitre.org/techniques/T1189"
    }
  ]
}
```

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
