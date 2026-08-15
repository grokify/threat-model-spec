# Deployment Report Profile

**Stage:** `deployment` · **Role:** builder · **Input mode:** `artifact-types`

## Purpose

Determine whether the deployed configuration preserves the design's assumptions. A threat can be controlled in code but reintroduced through deployment — a private administrative endpoint exposed by an ingress rule is the canonical example this stage exists to catch.

## Inputs

`ArtifactType`: `iac`, `deployment-manifest`.

## ASPM Overlay

Domains 6–9: `iac-scan`, `cicd-posture`, `container-security`, `artifact-security`.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Finding` | IaC misconfigurations, CI/CD posture gaps, container/artifact issues — each tagged with `aspmDomainId` |
| `ArchitectureAssertion` | Deployed-vs-designed exposure drift (e.g. `subjectId: admin-api`, `predicate: network-exposure`, `expected: private`, `observed: public`) |

## Coverage Checks

- `all-aspm-domains-covered` — every ASPM domain with `primaryStage == deployment` was analyzed
- `has-evidence-per-finding` — every Finding cites at least one Evidence ID
- `has-deployed-control-verification` — controls required by Builder Definition are checked against the actual deployed configuration, not just the source

## Rubric

`deployment` (`evaluation/rubrics/stages/deployment.rubric.json`).
