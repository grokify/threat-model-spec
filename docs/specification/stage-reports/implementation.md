# Implementation Report Profile

**Stage:** `implementation` · **Role:** builder · **Input mode:** `artifact-types`

## Purpose

Determine whether the code satisfies the Builder Definition technical contract, and surface evidence-backed vulnerabilities, weaknesses, and drift found by analyzing the actual source tree — not planning documents. This is the first stage where TMS *consumes* scanner output (SAST, SCA, secret scanning, SBOM generation) rather than producing planning-time claims.

## Inputs

`ArtifactType`: `source-tree`, `dependency-manifest`, `sbom`.

## ASPM Overlay

Domains 1–5: `git-posture`, `code-security`, `secret-pii-scan`, `open-source-security`, `sbom`. Findings should carry `aspmDomainId` so coverage per domain is measurable.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Finding` | Vulnerabilities, weaknesses, control gaps — each tagged with `aspmDomainId` and cited `evidenceIds` |
| `ArchitectureAssertion` | Design-vs-implementation drift (e.g. "the tech spec says every tenant lookup is scoped by `tenant_id`, but this handler retrieves by object ID alone") |

## Coverage Checks

- `all-aspm-domains-covered` — every ASPM domain with `primaryStage == implementation` was actually analyzed (or explicitly marked not-applicable)
- `has-evidence-per-finding` — every Finding cites at least one Evidence ID
- `has-drift-check` — at least one ArchitectureAssertion compares implementation to the Builder Definition design

## Rubric

`implementation` (`evaluation/rubrics/stages/implementation.rubric.json`).
