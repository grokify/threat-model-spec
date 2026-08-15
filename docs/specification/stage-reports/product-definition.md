# Product Definition Report Profile

**Stage:** `product-definition` · **Role:** product · **Input mode:** `workflow-specs`

## Purpose

Establish the security-relevant facts about *what is being built and for whom*, before any technical design exists: valuable assets, the actors who can affect them, plausible abuse scenarios, and the invariants the product must never violate.

## Inputs

Whatever specs a workflow categorizes into the `product-definition` PDLC stage — typically PRD, MRD, UXD, press release, FAQ, six-pager, opportunity spec. Resolved via the specification-workflow-spec registry (`SpecType.PDLCStage`); this profile enumerates no spec-type list of its own.

## Output Objects

| IR type | What it captures |
|---------|-------------------|
| `Asset` | Sensitive data, credentials, services worth protecting |
| `ThreatActor` | Adversary profiles relevant to this product |
| `Scenario` | Abuse/fraud what-if cases |
| `SecurityRequirement` | Invariants, prohibited outcomes, and privacy requirements, with `originArtifactId` pointing at the spec they came from |

## Coverage Checks

- `has-assets` — at least one Asset identified
- `has-invariant` — at least one `SecurityRequirement` of type `invariant`
- `has-threat-actor` — at least one ThreatActor profile
- `has-prohibited-outcome` — at least one `SecurityRequirement` of type `prohibited-outcome`

## Rubric

`product-definition` (`evaluation/rubrics/stages/product-definition.rubric.json`).

## Example

> "A merchant must never access another merchant's customers" (SecurityRequirement, type `invariant`, originating from the PRD's tenancy section) — this is the kind of claim a Product Definition report should surface, not a generic "the product should be secure."
