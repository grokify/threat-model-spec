# D2TM - D2 Threat Modeling Library

## Product Requirements Document

### Overview

D2TM is an open-source Go library and D2 style collection for creating security threat modeling diagrams using the D2 diagramming language. It provides reusable styles, Go types, and templates for STRIDE threat modeling, Data Flow Diagrams (DFDs), trust boundaries, and attack chain visualization.

### Problem Statement

Security professionals need to create threat modeling diagrams that:

1. Are version-controllable (diagrams-as-code)
2. Export to high-quality SVG
3. Follow security standards (STRIDE, MITRE ATT&CK)
4. Can be generated programmatically
5. Are reusable across projects

Existing tools either require GUIs (Threat Dragon), lack security-specific semantics (generic diagramming), or don't support code-based workflows.

### Goals

1. **Diagrams-as-Code**: All diagrams defined in text files (D2 format)
2. **Security-First**: Purpose-built for threat modeling with STRIDE, DFD, and attack chain support
3. **Reusable Styles**: Import once, use across all diagrams
4. **Go Integration**: Generate D2 diagrams programmatically from Go
5. **Standards Alignment**: Map to MITRE ATT&CK, Cyber Kill Chain

### Non-Goals

1. GUI diagram editor (use existing D2 tooling)
2. Automated threat detection (this is visualization, not analysis)
3. Runtime security monitoring

### Target Users

- Security engineers creating threat models
- Red team members documenting attack chains
- Developers adding security diagrams to documentation
- Security researchers publishing vulnerability analyses

### Use Cases

#### UC1: Threat Model Diagram

Security engineer creates a DFD with trust boundaries and STRIDE annotations for a web application architecture review.

#### UC2: Attack Chain Visualization

Red team documents a multi-stage attack chain with MITRE ATT&CK mapping for a penetration test report.

#### UC3: Vulnerability Disclosure Diagram

Security researcher creates a clear visual explanation of a vulnerability for a responsible disclosure report.

#### UC4: Programmatic Generation

CI/CD pipeline generates threat model diagrams from infrastructure-as-code definitions.

### Requirements

#### Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1 | D2 style library for STRIDE threat types | P0 |
| FR2 | D2 style library for DFD elements (process, datastore, external entity) | P0 |
| FR3 | D2 style library for trust boundaries | P0 |
| FR4 | D2 style library for attack flows | P0 |
| FR5 | Go types for STRIDE threats | P1 |
| FR6 | Go types for DFD elements | P1 |
| FR7 | Go types for MITRE ATT&CK tactics/techniques | P1 |
| FR8 | Go function to render diagram to D2 format | P1 |
| FR9 | Example: OpenClaw attack chain diagram | P0 |
| FR10 | D2 layer support for threat overlays | P2 |

#### Non-Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NFR1 | All D2 styles must render correctly to SVG | P0 |
| NFR2 | Go code must pass golangci-lint | P0 |
| NFR3 | Library must work with D2 v0.6+ | P0 |
| NFR4 | Documentation with usage examples | P1 |

### Demo Requirements (Educational)

To demonstrate a real-world vulnerability (OpenClaw WebSocket takeover):

| ID | Requirement | Priority |
|----|-------------|----------|
| DR1 | Vulnerable WebSocket server (mimics OpenClaw flaw) | P1 |
| DR2 | Malicious HTML page with attack JavaScript | P1 |
| DR3 | Browser automation to prove attack (Vibium-go) | P2 |
| DR4 | Clear educational warnings in demo code | P0 |

### Success Metrics

1. D2 styles render correctly in D2 CLI and online playground
2. OpenClaw attack chain diagram clearly shows the vulnerability
3. Demo successfully demonstrates localhost WebSocket takeover
4. Library is usable by other security projects

### Dependencies

| Dependency | Purpose | Required |
|------------|---------|----------|
| D2 CLI | Rendering D2 to SVG | Yes (runtime) |
| Go 1.24+ | Go library | Yes |
| Vibium-go | Browser automation for demo | Optional |
| gorilla/websocket | Vulnerable server demo | Optional |

### References

- [D2 Language](https://d2lang.com)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OpenClaw Vulnerability](https://www.oasis.security/blog/openclaw-vulnerability)
