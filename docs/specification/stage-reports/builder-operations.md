# Builder Operations Report Profile

**Stage:** `builder-operations` · **Role:** builder · **Input mode:** `artifact-types`

## Purpose

Assess infrastructure, security, and reliability operations for the deployed system: is it exploitable under realistic conditions, and would the organization detect and respond if it were attacked? Runs in parallel with Product Operations, not sequentially after it — both are fed by the same deployed system but ask different questions.

## Inputs

`ArtifactType`: `runtime-endpoint`, `telemetry`, `incident`.

## ASPM Overlay

Domain 10: `cloud-context` (CSPM — IAM, network exposure, logging posture). Dynamic testing (DAST, penetration testing, red teaming) sits alongside this domain and is explicitly *not* an ASPM domain — ASPM is the static-posture slice; dynamic testing is a complementary analysis mode over the same stage.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Finding` | Detection gaps, exploitability results, observed techniques, control-effectiveness gaps |

## Coverage Checks

- `has-detection-coverage` — detection coverage was assessed for the techniques relevant to this product
- `has-incident-evidence` — where an incident artifact exists, at least one Finding cites it
- `has-dynamic-testing-note` — the report states whether dynamic testing (DAST/pen test/red team) was in scope for this run, so its absence is never silently read as "nothing found"

## Rubric

`builder-operations` (`evaluation/rubrics/stages/builder-operations.rubric.json`).
