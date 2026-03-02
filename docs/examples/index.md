# Examples

Threat Model Spec includes complete examples demonstrating real-world threat modeling scenarios.

## Available Examples

| Example | Description | Diagram Types |
|---------|-------------|---------------|
| [OpenClaw](openclaw/index.md) | WebSocket localhost takeover | DFD, Attack Chain, Sequence |

## OpenClaw Case Study

The OpenClaw example demonstrates a critical vulnerability in a popular AI agent application:

- **Vulnerability:** WebSocket localhost takeover
- **Severity:** Critical (CVSS 9.3)
- **Discovered by:** Oasis Security
- **Impact:** Full agent compromise, data exfiltration

### What You'll Learn

1. Creating Data Flow Diagrams (DFD) with trust boundaries
2. Building attack chains with MITRE ATT&CK mapping
3. Documenting attack sequences
4. Mapping to multiple security frameworks (STRIDE, OWASP, CWE)
5. Generating D2 diagrams and STIX 2.1 exports

### Quick Start

```bash
# Navigate to the example
cd examples/openclaw

# Generate attack chain diagram
tms generate attack_chain.json -o attack_chain.d2 --svg

# Export to STIX 2.1
tms generate attack_chain.json --stix -o attack_chain.stix.json
```

## Creating Your Own Examples

Follow this pattern for new threat models:

1. **Define the threat model** in JSON
2. **Generate diagrams** with `tms generate`
3. **Validate** with `tms validate --strict`
4. **Export to STIX** for threat intelligence sharing

### Example Structure

```
examples/
└── your-example/
    ├── README.md           # Documentation
    ├── dfd.json            # Data flow diagram
    ├── attack_chain.json   # Attack chain
    ├── sequence.json       # Sequence diagram
    └── *.svg               # Generated diagrams
```
