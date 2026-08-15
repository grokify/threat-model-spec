# threat-model-spec-toolkit - Kiro CLI Plugin

Multi-agent team for D2 threat modeling diagrams (DFDs, attack flows, sequence diagrams with STRIDE/MITRE ATT&CK/OWASP annotations) and PDLC stage analysis (product-definition through product-operations) via tms analyze

## Agents

| Agent | Description |
|-------|-------------|
| `attack-flow-visualizer` | Creates attack chain and attack flow diagrams with MITRE ATT&CK/ATLAS and STRIDE annotations |
| `builder-definition-analyst` | Produces a Builder Definition-stage threat model analysis report from technical specs (TRD/TPD/IRD), mapping trust boundaries, STRIDE threats, and required controls |
| `builder-operations-analyst` | Produces a Builder Operations-stage threat model analysis report from runtime telemetry and incident data, assessing detection coverage and control effectiveness against actual production behavior |
| `deployment-analyst` | Produces a Deployment-stage threat model analysis report from IaC and deployment manifests, verifying designed controls actually hold in the deployed configuration |
| `dfd-creator` | Creates Data Flow Diagrams for threat modeling with numbered flows, trust boundaries, and proper legend design |
| `diagram-quality-reviewer` | Reviews D2 threat model diagrams for layout quality, whitespace optimization, legend clarity, and visual effectiveness |
| `implementation-analyst` | Produces an Implementation-stage threat model analysis report from source code, dependency manifests, and SBOMs, covering the five implementation-side ASPM domains |
| `product-definition-analyst` | Produces a Product Definition-stage threat model analysis report from product specs (PRD/UXD/MRD/etc.), identifying assets, threat actors, abuse scenarios, and security invariants |
| `product-operations-analyst` | Produces a Product Operations-stage threat model analysis report from usage telemetry and incidents, checking Product Definition's invariants against production reality and tracking adoption signal |

## Usage

Run an agent with the Kiro CLI:

```bash
kiro-cli chat --agent attack-flow-visualizer "<your prompt>"
```

## Steering Files

Copy steering files to `.kiro/steering/` for automatic context loading:

```bash
mkdir -p .kiro/steering
cp steering/*.md .kiro/steering/
```

## Installation

Copy agents to your Kiro agents directory:

```bash
mkdir -p ~/.kiro/agents
cp agents/*.json ~/.kiro/agents/
```
