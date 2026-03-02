# D2TM Development Tasks

## Phased Approach

### Phase 1: D2 Style Library (Core)

Create the foundational D2 style files that can be imported into any D2 diagram.

| Task | Status | Description |
|------|--------|-------------|
| 1.1 | [x] | Create `d2/styles/stride.d2` - STRIDE threat annotation styles |
| 1.2 | [x] | Create `d2/styles/dfd.d2` - DFD element styles (process, datastore, external entity) |
| 1.3 | [x] | Create `d2/styles/trustboundary.d2` - Trust boundary styles |
| 1.4 | [x] | Create `d2/styles/attackflow.d2` - Attack flow and kill chain styles |
| 1.5 | [x] | Create `d2/styles/all.d2` - Combined import file |
| 1.6 | [x] | Test styles render correctly with D2 CLI |

**Deliverable**: Reusable D2 style library - **COMPLETE**

### Phase 2: OpenClaw Diagram Example

Build the attack chain diagram for the OpenClaw vulnerability using the style library.

| Task | Status | Description |
|------|--------|-------------|
| 2.1 | [x] | Create `examples/openclaw/attack_chain.d2` - Full attack chain diagram |
| 2.2 | [x] | Add STRIDE threat annotations to diagram |
| 2.3 | [x] | Add MITRE ATT&CK mapping as comments/notes |
| 2.4 | [x] | Generate SVG output |
| 2.5 | [x] | Create `examples/openclaw/README.md` - Explanation of the vulnerability |

**Deliverable**: OpenClaw attack chain diagram (D2 + SVG) - **COMPLETE**

### Phase 3: Go Library

Add Go types and code generation for programmatic diagram creation.

| Task | Status | Description |
|------|--------|-------------|
| 3.1 | [x] | Create `stride/stride.go` - STRIDE threat types |
| 3.2 | [x] | Create `killchain/mitre.go` - MITRE ATT&CK tactics/techniques |
| 3.3 | [x] | Create `killchain/lockheed.go` - Cyber Kill Chain phases |
| 3.4 | [x] | Create `diagram/element.go` - DFD element types |
| 3.5 | [x] | Create `diagram/boundary.go` - Trust boundary types |
| 3.6 | [x] | Create `diagram/flow.go` - Data flow types |
| 3.7 | [x] | Create `diagram/diagram.go` - Main diagram type |
| 3.8 | [x] | Create `diagram/render.go` - D2 code generation |
| 3.9 | [x] | Add unit tests (40 tests passing) |
| 3.10 | [x] | Run golangci-lint (0 issues) |

**Deliverable**: Go library for D2 threat model generation - **COMPLETE**

### Phase 4: Vulnerable Demo Service

Create a simple WebSocket server that mimics OpenClaw's vulnerable behavior for educational demonstration.

| Task | Status | Description |
|------|--------|-------------|
| 4.1 | [x] | Create `demo/vulnerable-server/main.go` - WebSocket server |
| 4.2 | [x] | Implement password auth (no rate limiting) |
| 4.3 | [x] | Implement auto-approve device pairing from localhost |
| 4.4 | [x] | Return mock config/logs on authenticated commands |
| 4.5 | [x] | Add `demo/vulnerable-server/README.md` with warnings |

**Server Behavior**:
- Listen on `localhost:9999`
- WebSocket endpoint: `/ws`
- Password: `demo123` (intentionally weak)
- No rate limiting on auth attempts
- Auto-approve device registration from localhost
- Return mock data on successful auth

**Deliverable**: Educational vulnerable WebSocket server - **COMPLETE**

### Phase 5: Attack Demonstration

Create the attack page and automation to prove the vulnerability works.

| Task | Status | Description |
|------|--------|-------------|
| 5.1 | [x] | Create `demo/malicious-page/index.html` - Attack page with JS |
| 5.2 | [x] | Implement WebSocket connection to localhost |
| 5.3 | [x] | Implement password brute-force loop |
| 5.4 | [x] | Implement device registration after auth |
| 5.5 | [x] | Implement data exfiltration display |
| 5.6 | [x] | Create `demo/attacker/main.go` - Vibium-go automation |
| 5.7 | [x] | Automate: launch browser, serve page, capture result |
| 5.8 | [x] | Add screenshot/recording of successful attack |

**Deliverable**: End-to-end attack demonstration - **COMPLETE**

### Phase 6: Documentation and Polish

| Task | Status | Description |
|------|--------|-------------|
| 6.1 | [ ] | Write main README.md |
| 6.2 | [ ] | Add Go documentation comments |
| 6.3 | [ ] | Create example usage snippets |
| 6.4 | [ ] | Add CI workflow (.github/workflows) |

**Deliverable**: Production-ready library

---

## Current Focus

**Active Phase**: Phase 6 - Documentation and Polish

**Completed**: Phase 1 (D2 Styles), Phase 2 (OpenClaw Example), Phase 3 (Go Library), Phase 4 (Vulnerable Server), Phase 5 (Attack Demonstration)

**Next Action**: Write main README.md and add CI workflow

---

## Architecture

```
d2tm/
├── d2/
│   ├── styles/
│   │   ├── stride.d2           # STRIDE threat styles
│   │   ├── dfd.d2              # DFD element styles
│   │   ├── trustboundary.d2    # Trust boundary styles
│   │   ├── attackflow.d2       # Attack flow styles
│   │   └── all.d2              # Combined import
│   └── templates/
│       └── threat_model.d2     # Full template
├── stride/
│   └── stride.go               # Go STRIDE types
├── killchain/
│   ├── mitre.go                # MITRE ATT&CK
│   └── lockheed.go             # Cyber Kill Chain
├── diagram/
│   ├── element.go              # DFD elements
│   ├── boundary.go             # Trust boundaries
│   ├── flow.go                 # Data flows
│   ├── diagram.go              # Main type
│   └── render.go               # D2 generation
├── examples/
│   └── openclaw/
│       ├── attack_chain.d2     # Example diagram
│       ├── attack_chain.svg    # Rendered output
│       └── README.md
└── demo/
    ├── vulnerable-server/      # Mock OpenClaw
    ├── malicious-page/         # Attack HTML/JS
    └── attacker/               # Vibium automation
```

---

## Notes

- All demo code includes clear warnings that it is for educational purposes only
- The vulnerable server only listens on localhost and has no real functionality
- Attack demonstration requires explicit user action to run
