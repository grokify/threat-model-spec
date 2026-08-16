# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — Plan

> **Status:** ✅ Phase 1 Complete · Phase 2 Cancelled · Phase 3 Deferred
>
> **Goal:** Close the residual gaps from INIT-THREATMODELSPEC-002's success-metric review — structured framework categorization, prohibited-outcome authoring, and CLI docs. Persistence (originally planned as opt-in embedded Dolt inside this repo) was cancelled and redirected to a `visionstudio-cloud` initiative — see TRD §4. Empirical dogfooding remains deferred until a qualifying target is named.

## Implementation Order

Phase 1 executed in roadmap order; RMI-200 blocked RMI-201 (the computation reads the new fields), while RMI-202/203/210 were independent and interleaved.

1. **RMI-200** — Finding fields + validation + schema regen (foundation for 201) — done
2. **RMI-201** — `ComputeCoverageChecks` + tms wiring + agent-spec/plugin updates — done
3. **RMI-202** — prohibited-outcome spike → resolution — done
4. **RMI-203** — CLI reference pages — done
5. **RMI-210** — Lifecycle IR objects documentation (added mid-phase) — done
6. ~~RMI-204/205/206~~ — cancelled; see TRD §4
7. **Phase 3 (207–209)** — deferred; starts when a dogfood target satisfying the data requirements is named

## Verification Gates

Every commit batch: `go build ./... && go vet ./... && go test ./... && gofmt -l . && golangci-lint run` clean; `mkdocs build --strict` for doc-touching changes; `TestExamplesValidate` green with zero example edits before any deliberate retrofits.

Phase-1 exit (met): both dogfood models pass `has-stride-mapping`/`has-prohibited-outcome` via computed checks; all seven CLI verbs documented.

## Success Criteria

PRD § Success Metrics. A close-out review is still owed (folded into whatever RMI eventually closes this initiative, given Phase 2's cancellation and Phase 3's deferral — see ROADMAP.md).
