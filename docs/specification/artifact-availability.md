# Artifact-Availability Profiles

Analysis adapts to what you have. An `ArtifactAvailabilityProfile` declares which artifact types are typically available for an analysis target, and which of the six PDLC stages that availability permits analyzing. `AnalysisRun.Profile` records which profile governed a given run, so every report is traceable to the evidence basis it was produced under — a third-party assessment's silence about implementation-stage findings should never be misread as "nothing was found," when the real reason is "nothing could be looked at."

The machine-readable form lives in the `ir` package (`ir/artifactavailability/*.json`), accessed via `ir.ArtifactAvailabilityProfiles()` / `ir.ArtifactAvailabilityProfileByProfile(profile)`.

## The Three Profiles

### `first-party`

Full artifact access: specs, code, IaC, deployment manifests, telemetry, and incident records. All six stages can be credibly analyzed. This is the profile for assessing your own product.

### `third-party`

Public documentation and a live site only — typical of assessing a vendor or partner product you don't control.

| Permitted | Not analyzable |
|-----------|-----------------|
| `product-definition` (public docs) | `builder-definition` — no access to internal technical specs |
| `deployment` (external observation) | `implementation` — no access to source code |
| `builder-operations` (external observation) | `product-operations` — no access to internal telemetry or incident data |

### `open-source`

Public documentation and source code — typical of assessing an open-source dependency.

| Permitted | Not analyzable |
|-----------|-----------------|
| `product-definition` (README/design docs) | `deployment` — no visibility into how downstream users deploy it |
| `builder-definition` (design docs) | `builder-operations` — no visibility into any specific runtime posture |
| `implementation` (source tree) | `product-operations` — no visibility into production usage or telemetry |

## Guarantee

Every PDLC stage is accounted for in every profile: it is either in `permittedStages`, or in `notAnalyzableStages` with an explicit reason. There is no stage a profile is silent about — the `TestArtifactAvailabilityProfiles_EveryStageAccountedFor` test in `ir/artifact_availability_test.go` enforces this for the three canonical profiles.

## Relationship to Stage Report Profiles

A [StageReportProfile](stage-reports/index.md) defines *what* a stage's report contains once analysis runs; an `ArtifactAvailabilityProfile` defines *whether* that stage can credibly be analyzed at all, given what's available for the target. `tms analyze --stage <s> --profile <p>` consults both: the artifact-availability profile gates whether the run proceeds, and the stage report profile shapes what it produces.
