# Product Operations Report Profile

**Stage:** `product-operations` · **Role:** product · **Input mode:** `artifact-types`

## Purpose

Reconcile the approved Product Definition's security invariants against what's actually happening in production: adoption and usage signal, abuse/fraud patterns, and drift between the invariants the product promised and the reality observed. This is where the lifecycle closes back to Product Definition — a validated Finding here can trigger the next baseline revision. Runs in parallel with Builder Operations, not sequentially after it.

## Inputs

`ArtifactType`: `telemetry`, `incident`.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Finding` | Abuse/fraud signal observed in production; adoption-driven risk changes |
| `ArchitectureAssertion` | Invariant drift: `expected` = the SecurityRequirement's statement, `observed` = what production telemetry shows |

## Coverage Checks

- `has-invariant-drift-check` — every `critical`-criticality SecurityRequirement from Product Definition has at least one corresponding ArchitectureAssertion checked against production reality
- `has-adoption-signal` — the report includes adoption/usage signal, not solely incident-driven findings, so an absence of incidents is never mistaken for validated safety

## Rubric

`product-operations` (`evaluation/rubrics/stages/product-operations.rubric.json`).
