# Stage Analysis Report Profiles

A Threat Model Spec Analysis Report is what an agent produces when it analyzes one [PDLC](https://github.com/ProductBuildersHQ/pdlc) stage of a product. Each of the six stages has a normative **report profile**: what inputs it requires, what IR objects a compliant report must populate, the deterministic completeness checks it must pass, and the rubric it is graded against.

The machine-readable form of every profile is embedded in the `ir` package (`ir/stagereports/*.json`) and accessed via `ir.StageReportProfiles()` / `ir.StageReportProfileByStage(stage)`. This directory is the normative narrative; the embedded JSON is the source of truth a `tms analyze` implementation reads at runtime.

## The Six Stages

| Stage | Role | Input mode | ASPM domains |
|-------|------|-----------|---------------|
| [Product Definition](product-definition.md) | product | workflow specs | — |
| [Builder Definition](builder-definition.md) | builder | workflow specs | — |
| [Implementation](implementation.md) | builder | artifact types | git-posture, code-security, secret-pii-scan, open-source-security, sbom |
| [Deployment](deployment.md) | builder | artifact types | iac-scan, cicd-posture, container-security, artifact-security |
| [Builder Operations](builder-operations.md) | builder | artifact types | cloud-context |
| [Product Operations](product-operations.md) | product | artifact types | — |

## Input Modes

Every profile declares an `inputMode`:

- **`workflow-specs`** — the two spec-driven stages (Product Definition, Builder Definition) consume whatever specs a workflow categorizes into that stage, resolved via the [visionspec](https://github.com/ProductBuildersHQ/visionspec) registry. The profile declares no spec-type list of its own — see the [PDLC Threat Modeling design](../../design/) for why this keeps threat-model-spec decoupled from individual spec workflows.
- **`artifact-types`** — the four builder-side stages consume non-spec artifacts (code, IaC, deployment manifests, telemetry, incidents) enumerated directly on the profile.

## ASPM Overlay

The three stages carrying an Application Security Posture Management (ASPM) overlay — Implementation, Deployment, Builder Operations — declare the `aspmDomainIds` their reports organize findings by. See `ir.ASPMDomains()` for the full ten-domain registry and each domain's primary stage.
