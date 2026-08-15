# Builder Definition Report Profile

**Stage:** `builder-definition` · **Role:** builder · **Input mode:** `workflow-specs`

## Purpose

Turn the approved Product Baseline into a technical threat model: components, data flows, trust boundaries, and the STRIDE/LINDDUN threats they imply, plus the controls required to address them. This stage also verifies that the finalized API contract hasn't drifted from Product Definition's advisory draft — the same normative-spec-plus-advisory-evidence pattern pdlc uses for this stage (finalized OpenAPI contract normative, generated reference SDK client advisory).

## Inputs

Whatever specs a workflow categorizes into the `builder-definition` PDLC stage — typically TRD, IRD, TPD, architecture specs. Resolved via the specification-workflow-spec registry; this profile enumerates no spec-type list of its own.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Finding` | STRIDE/LINDDUN threats, type `threat-candidate` |
| `Mitigation` | Required controls addressing each threat |
| `ArchitectureAssertion` | The API-contract-drift check: `expected` = Product Definition's draft, `observed` = the finalized contract |
| `SecurityRequirement` | `verificationIds` updated to reference this stage's analysis runs |

## Coverage Checks

- `has-trust-boundaries` — the model's diagrams declare at least one trust boundary
- `has-stride-mapping` — every trust-boundary-crossing flow has at least one STRIDE-mapped Finding
- `has-required-controls` — every validated threat-candidate Finding has at least one Mitigation
- `has-api-contract-drift-check` — an ArchitectureAssertion exists comparing the API contract to the Product Definition draft

## Rubric

`builder-definition` (`evaluation/rubrics/stages/builder-definition.rubric.json`).
