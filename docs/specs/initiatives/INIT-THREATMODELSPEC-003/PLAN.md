# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — Plan

> **Status:** 🚧 In Progress
>
> **Goal:** Close the residual gaps from INIT-THREATMODELSPEC-002's success-metric review — structured framework categorization, prohibited-outcome authoring, CLI docs, and opt-in DoltDB persistence — releasing as v0.9.0; empirical dogfooding deferred until a qualifying target is named.

## Implementation Order

Phases execute in roadmap order; within Phase 1, RMI-200 blocks RMI-201 (the computation reads the new fields), while RMI-202 and RMI-203 are independent and can interleave.

1. **RMI-200** — Finding fields + validation + schema regen (foundation for 201)
2. **RMI-201** — `ComputeCoverageChecks` + tms wiring + agent-spec/plugin updates
3. **RMI-202** — prohibited-outcome spike → resolution (independent)
4. **RMI-203** — CLI reference pages (independent)
5. **RMI-204** — store package (Ent + embedded Dolt)
6. **RMI-205** — tms integration + `tms history` + parity tests
7. **RMI-206** — v0.9.0 release per repo release workflow
8. **Phase 3 (207–209)** — deferred; starts when a dogfood target satisfying the data requirements is named

## Verification Gates

Every commit batch: `go build ./... && go vet ./... && go test ./... && gofmt -l . && golangci-lint run` clean; `mkdocs build --strict` for doc-touching changes; `TestExamplesValidate` green with zero example edits before any deliberate retrofits.

Phase-1 exit: both dogfood models pass `has-stride-mapping`/`has-prohibited-outcome` via computed checks; all seven CLI verbs documented.

Phase-2 exit: store round-trip test green on all three CI OSes; disabled-store parity test proves byte-identical output; v0.9.0 tagged after CI, recorded in visionstudio.

## Success Criteria

PRD § Success Metrics, verified with evidence in RMI-209's review (same discipline as INIT-002's SUCCESS-METRICS-REVIEW.md).
