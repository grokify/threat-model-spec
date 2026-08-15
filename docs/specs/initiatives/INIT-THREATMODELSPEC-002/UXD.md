# UXD — PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows

**Initiative:** `INIT-THREATMODELSPEC-002`

The "users" of a spec + CLI product are humans reading reports, agents producing them, and tools consuming them. This UXD covers the experience surfaces: CLI verbs, report readability, workflow-definition ergonomics, and the failure/partial-data experience.

## Personas

| Persona | Context | Primary surface |
|---------|---------|-----------------|
| Sam, security engineer | Reviews graded findings across ~20 repos; time-poor | Markdown reports, gate summaries, diagrams |
| An analysis agent | Executes a stage workflow definition; needs unambiguous contracts | Workflow definition files, JSON Schema, validation errors |
| Jordan, staff engineer | Assesses a third-party vendor and an OSS dependency | `tms analyze` with partial profiles, framework exports |
| A pipeline (CI) | Runs validation and gate evaluation on model changes | `tms validate`, `tms gate`, exit codes, JSON output |

## CLI Experience

Extend `tms` with lifecycle verbs (names two-way-door; shapes below illustrative):

```bash
# Run a stage analysis: the invoking AI agent (Claude Code) does the reasoning;
# tms loads the stage profile + inputs, drives the workflow, writes the run, grades it
tms analyze threat-model.json --stage builder-definition --profile first-party ./docs/specs/

# Validate a lifecycle-aware model (schema + referential integrity + stage rules)
tms validate threat-model.json

# Show lifecycle state: stages analyzed, runs, gate status, open findings
tms status threat-model.json

# Evaluate a stage gate from recorded criteria; exit non-zero on failure (CI mode)
tms gate threat-model.json --stage deployment --ci

# Export framework reports
tms report threat-model.json --framework stride -o stride-report.md
tms report threat-model.json --framework attack --format json

# Show what analyses an artifact profile permits
tms profile third-party
```

Principles:

- **One writing verb; everything else reads.** All `tms` verbs but one render, validate, evaluate, and export — they never mutate a model. The single exception is `tms analyze`, which orchestrates a stage workflow: the invoking AI agent performs the analytical reasoning and `tms` writes the resulting analysis run into the model. `tms` itself performs no reasoning; humans and CI use only the read verbs.
- **Two output modes everywhere:** human (Markdown/terminal) and machine (JSON), selected with `--format`; exit codes meaningful in CI.
- **Errors name the object and the rule.** `finding:drift-004 references evidence:ing-77 which does not exist` — never a bare schema path.

## Report Readability (Sam's experience)

Stage analysis reports and framework exports are read far more often than written. Requirements:

1. **Lead with the verdict.** Every report opens with: stage, target, artifact profile, producer, judge grade, gate status — before any detail.
2. **Evidence one hop away.** Every finding shows its evidence excerpt inline with a stable locator (`deploy/ingress.yaml:18-31`), not just an ID.
3. **Drift is visually distinct.** Contradicted architecture assertions (design says private, deployment says public) render as expected-vs-observed pairs — the highest-value output for a human reviewer.
4. **Partial scope is explicit.** A third-party report states what was *not* analyzable ("no implementation evidence: source unavailable under third-party profile") so absence of findings is never read as absence of risk.
5. **Judge disagreement surfaces.** When multiple judges assess a claim, the report shows the spread, not just a mean.

## Agent Ergonomics (workflow-definition experience)

Agents succeed when the contract is unambiguous:

- Each stage workflow definition states: required artifact types, optional artifact types, analysis steps, the exact IR object types to emit, and the rubric it will be graded by — in one file.
- Output contracts are JSON Schema fragments the agent can validate against *before* submitting; validation errors are the same ones `tms validate` produces.
- The "insufficient evidence" path is first-class: an agent that cannot support a claim is told to emit it with low confidence or omit it — never to guess. Rubrics reward calibrated uncertainty.
- Workflow definitions include one worked example (input artifact excerpt → emitted objects) per stage.
- Agent specs are agnostic and generated: each per-stage workflow is authored once as a `multi-agent-spec` definition in `agents/specs/`, and `assistantkit` generates the Claude Code / Kiro / Gemini plugins in `agents/plugins/`. A user invokes a stage analysis in their tool of choice and it calls `tms analyze` — no per-tool glue code, and no tool gets a privileged hand-authored path.

## Third-Party / OSS Assessment Journey (Jordan)

1. `tms profile third-party` — sees permitted analyses: product-definition (from public docs), deployment/operations (external observation), no implementation stage.
2. Runs the product-definition and deployment agent workflows against docs and the live site.
3. Gets a model whose reports carry `profile: third-party` and explicit not-analyzed scope.
4. Exports an OWASP checklist and STRIDE coverage report for the vendor-review meeting.

The same journey with `open-source` swaps deployment analysis for implementation analysis over the source tree.

## Anti-Goals

- No GUI or TUI dashboards in this initiative (visionstudio/consumers may build them on the JSON).
- No interactive wizard flows; agents are the authors.
- No colorized-terminal investment beyond what render libraries already provide.

## Open UX Questions

- Whether `tms status` should render a lifecycle diagram (D2) in addition to text.
- Markdown report templates: per-stage bespoke vs. one template parameterized by stage (leaning: one template, stage sections).
