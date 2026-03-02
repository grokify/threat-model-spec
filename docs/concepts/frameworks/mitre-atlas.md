# MITRE ATLAS

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is a knowledge base of adversary tactics and techniques targeting machine learning systems.

## Overview

ATLAS extends MITRE ATT&CK concepts to AI/ML-specific threats, covering:

- Machine learning model attacks
- Data poisoning
- Model extraction
- Adversarial examples
- Prompt injection (LLMs)

## Tactics

| ID | Tactic | Description |
|----|--------|-------------|
| AML.TA0000 | ML Attack Staging | Preparing for ML attacks |
| AML.TA0001 | ML Model Access | Gaining access to ML models |
| AML.TA0002 | ML Artifact Collection | Collecting ML-related data |
| AML.TA0003 | ML Attack Execution | Executing attacks on ML systems |

## Common Techniques

| ID | Name | Description |
|----|------|-------------|
| AML.T0024 | Prompt Injection | Manipulating LLM behavior via crafted prompts |
| AML.T0025 | Model Extraction | Stealing ML model parameters |
| AML.T0020 | Data Poisoning | Corrupting training data |
| AML.T0043 | Adversarial Examples | Crafted inputs causing misclassification |
| AML.T0044 | Backdoor Attack | Inserting hidden behaviors |

## JSON Mapping Format

```json
{
  "mappings": {
    "mitreAtlas": [
      {
        "tacticId": "AML.TA0002",
        "tacticName": "ML Artifact Collection",
        "techniqueId": "AML.T0024",
        "techniqueName": "Prompt Injection",
        "description": "Crafted prompts manipulate AI agent behavior",
        "url": "https://atlas.mitre.org/techniques/AML.T0024"
      }
    ]
  }
}
```

## Use Cases

### AI Agent Security

```json
{
  "type": "attack-chain",
  "title": "AI Agent Compromise",
  "mappings": {
    "mitreAtlas": [
      {
        "techniqueId": "AML.T0024",
        "techniqueName": "Prompt Injection"
      }
    ],
    "owasp": [
      {
        "category": "llm",
        "id": "LLM01:2023",
        "name": "Prompt Injection"
      }
    ]
  }
}
```

### Model Theft

```json
{
  "mappings": {
    "mitreAtlas": [
      {
        "techniqueId": "AML.T0025",
        "techniqueName": "Model Extraction",
        "description": "Attacker queries API to reconstruct proprietary model"
      }
    ]
  }
}
```

## STIX 2.1 Export

ATLAS mappings are exported as Attack Patterns:

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "name": "Prompt Injection",
  "external_references": [
    {
      "source_name": "mitre-atlas",
      "external_id": "AML.T0024",
      "url": "https://atlas.mitre.org/techniques/AML.T0024"
    }
  ]
}
```

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [ATLAS Navigator](https://atlas.mitre.org/navigator)
- [AI/ML Security Resources](https://atlas.mitre.org/resources)
