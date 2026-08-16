# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — PRD

**Initiative:** `INIT-THREATMODELSPEC-003`
**Repository:** `github.com/grokify/threat-model-spec`
**Workflow:** pbhq-lite

## Overview

INIT-THREATMODELSPEC-002 shipped the lifecycle-aware analysis IR, six stage report profiles/rubrics/agents, `tms analyze`, and framework reports, released as v0.8.0. Its own dogfooding and success-metric review ([SUCCESS-METRICS-REVIEW.md](../INIT-THREATMODELSPEC-002/SUCCESS-METRICS-REVIEW.md), RMI-THREATMODELSPEC-119) surfaced residual gaps that were logged rather than silently dropped. This initiative closes them.

## Problem Statement

Every gap below was discovered empirically — by real dogfood runs or by the release review — not speculated:

1. **`ir.Finding` has no structured framework categorization.** Both dogfood runs failed the `has-stride-mapping` coverage check for the same reason: the STRIDE category the analyst clearly reasoned about only ever lived in `Finding.Description` free text. There is nothing queryable, and the coverage check itself can only be self-reported, not computed.
2. **`prohibited-outcome` is never authored.** The `SecurityRequirementType` enum has carried `prohibited-outcome` since v0.8.0, yet neither dogfood run produced a single requirement typed with it — both runs' `has-prohibited-outcome` check failed identically. Either agent guidance never asks for it (authoring gap) or the invariant/prohibited-outcome distinction doesn't earn its keep (design gap).
3. **CLI documentation stops at v0.5.0-era verbs.** The MkDocs CLI Reference documents `generate` and `validate` only; `gate`, `analyze`, `report`, `status`, and `profile` — the verbs this whole initiative family added — have no doc pages.
4. **No analysis outlives the JSON file.** Judge runs, assessments, gates, and framework reports exist only inside a single ThreatModel document — no append-only history, no audit trail of who/what graded when, no way to query across models or over time. DoltDB persistence was deferred from INIT-002's TRD (§9) from day one. **Resolved by scoping this out of this repo entirely** — see Goals and TRD §4: this is a `visionstudio-cloud` premium-feature initiative, not a `threat-model-spec` one.
5. **Three stages have zero real-run evidence** (`deployment`, `builder-operations`, `product-operations`), and **`builder-definition`'s rubric has only proven discrimination synthetically** — real content scored uniformly all-pass in both runs. *Deferred: closing these requires a target with real IaC, a live endpoint, telemetry, and incident history — data this repo cannot supply itself.*

## Goals

- A `Finding`'s framework categorization (STRIDE, OWASP, ATT&CK) is structured, validated, and queryable — and the coverage checks that depend on it become deterministic computations instead of self-reports.
- `prohibited-outcome` requirements actually get authored (or the type distinction is consciously revised) — resolved by investigation, not assumption.
- Every `tms` verb has a reference page.
- The deferred dogfood work is specified with concrete data-requirements acceptance criteria so it can start the moment a qualifying target is named.

## Non-Goals

- **No persistence layer of any kind in this repo.** `threat-model-spec` stays a pure JSON IR spec plus a local, standalone `tms` CLI — no database, embedded or otherwise. Analysis history/aggregation as a premium capability is out of scope here; see TRD §4 for where it actually belongs (`visionstudio-cloud`).
- No reimplementation of SAST/DAST/SCA scanners (unchanged from INIT-002).
- No new stages, rubrics, or report profiles.
- Dogfooding the three untouched stages is **not promised by this initiative's release** — it is scoped, data-gated, and executes when a qualifying target exists.

## Functional Requirements

### FR1 — Structured framework categorization on Finding

- `ir.Finding` gains optional `strideCategories`, `owaspIds`, and `attackTechniqueIds` fields validated against the existing enum/validators (`STRIDEThreat`, `ValidateOWASPID`, `ValidateTechniqueID`).
- JSON Schema regenerated; all additions optional — every existing model validates unchanged.
- `tms` computes `has-stride-mapping` deterministically from the structured field during analyze/gate flows; agent specs updated to populate the fields.

### FR2 — prohibited-outcome resolution (spike)

- Determine root cause: authoring gap vs. type-design gap, with evidence from the two dogfood models and the agent specs.
- Expected outcome (authoring gap): product-definition agent spec gains explicit prohibited-outcome guidance and its worked example authors one; plugins regenerated; the flagship example models one.
- If instead a design gap: document the decision and adjust type docs — no silent enum removal.

### FR3 — CLI reference completeness

- `docs/cli/` gains per-command pages for `gate`, `analyze`, `report`, `status`, `profile`, in the established `generate`/`validate` page format, wired into mkdocs nav; strict build passes.

### FR4 — Persistence: cancelled, redirected

Originally scoped as a new embedded-Dolt storage package in this repo. Cancelled — see TRD §4 for the original design and the rationale for abandoning it. The actual capability (persisted, queryable analysis history) is redirected to a new `visionstudio-cloud` initiative, which is out of scope for this PRD.

### FR5 — Empirical dogfood (deferred, data-gated)

- Acceptance criteria are data requirements: a target with real IaC + deployment manifests, a reachable runtime endpoint, telemetry, and ≥1 incident record.
- builder-definition rubric discrimination: a real, deliberately-flawed-or-known-imperfect design target produces non-uniform category scores.

## Success Metrics

1. Both v0.8.0 dogfood models, re-analyzed (or minimally retrofitted), pass `has-stride-mapping` via the deterministic computation — no self-report.
2. The flagship example carries ≥1 `prohibited-outcome` requirement, or a documented design decision says why not.
3. `mkdocs build --strict` passes with all seven CLI verbs documented.
4. Existing v0.8.0 models validate unchanged against the regenerated schema.

## Dependencies

- INIT-THREATMODELSPEC-002 (released, v0.8.0) — all IR types, profiles, rubrics this builds on.
- FR5 additionally depends on a qualifying dogfood target being named (external to this repo).
