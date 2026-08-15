# Repo Cleanup — v0.7.0 Release Artifacts and Canonical Examples — Roadmap

**Initiative:** `INIT-THREATMODELSPEC-001`
**Repository:** `github.com/grokify/threat-model-spec`

> RMI IDs are stable and permanent. Commits implementing an item carry the trailer `Refs: RMI-<REPOSLUG>-<NNN>`. Phase status is derived from member RMIs — a phase is complete only when all its required RMIs are complete.

This initiative uses the RMI-THREATMODELSPEC-0xx block (INIT-THREATMODELSPEC-002 will use 1xx).

## Phase 1 — v0.7.0 Release Completion

**Theme:** Finish the v0.7.0 release per the repo release workflow so the tagged release has complete, correctly referenced artifacts

- [ ] `RMI-THREATMODELSPEC-001` Versioned v0.7.0 specification directory
  - Create docs/versions/v0.7.0/ with specification.md plus threat-model.schema.json and diagram.schema.json copied from schema/; add v0.7.0 entries to mkdocs.yml nav (Versions, Releases)
- [ ] `RMI-THREATMODELSPEC-002` README version references updated to v0.7.0
  - Specification table lists v0.7.0; feature section retitled or generalized (currently "v0.6.0 Security Enhancement Features"); quick-start $schema example points at v0.7.0
- [ ] `RMI-THREATMODELSPEC-003` Resolvable schema URLs
  - Replace broken github.com/.../docs/versions/... URLs (missing /blob/main/, serves HTML not JSON) with URLs that serve raw JSON — GitHub Pages (MkDocs site already exists) or raw.githubusercontent.com; update README and any $schema references; add a redirect/note for the old URLs

## Phase 2 — Canonical Examples

**Theme:** examples/ goes from empty to runnable, validated, and referenced — a user can clone and run tms against real threat models

- [ ] `RMI-THREATMODELSPEC-004` Flagship OpenClaw WebSocket takeover example
  - Complete ThreatModel JSON exercising diagrams (DFD, attack chain, attack tree), mappings (ATT&CK, OWASP, CWE), mitigations, assets, and red/blue team guidance; derived from the existing demo/ vulnerability
- [ ] `RMI-THREATMODELSPEC-005` Breadth examples: design-phase and supply-chain models
  - A design-phase (pre-implementation) DFD/STRIDE example and a supply-chain example using SBOM/VEX/dependency-risk fields; each with a short README explaining what it demonstrates
- [ ] `RMI-THREATMODELSPEC-006` Examples wired into CI and docs
  - Go test validates every examples/*.json via ir validation and schema; README quick start and MkDocs getting-started link to the example files; remove stray .DS_Store and gitignore it

## Phase 3 — Docs and Test Hygiene

**Theme:** Repository accurately describes the product and untested packages get coverage

- [ ] `RMI-THREATMODELSPEC-007` PRD rewritten to current product boundary
  - Replace stale D2TM visualization-only PRD with the current positioning: a data format/IR that standardizes security-analysis inputs, claims, evidence, and results; correct non-goals (spec does not perform SAST/DAST/monitoring — it represents their outputs); move IDEATION_CHAT_PDLC.md into docs/design/
- [ ] `RMI-THREATMODELSPEC-008` stix package tests
  - Unit tests for stix/ export and types (currently 0% coverage) covering bundle generation from a ThreatModel fixture
- [ ] `RMI-THREATMODELSPEC-009` schema and cmd package tests
  - schema/ embedded-schema validation test per org convention (schemas parse, match generated output); smoke tests for cmd/tms generate and validate paths against the canonical examples
