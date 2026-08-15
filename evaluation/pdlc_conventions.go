// Package evaluation: PDLC/structured-evaluation integration conventions.
//
// RMI-THREATMODELSPEC-105 gap assessment (TRD "structured-evaluation gap
// assessment", FR5.4): four candidate gaps were identified before this
// package depended on structured-evaluation v0.13.0 for real. Verified
// against the actual v0.13.0 API, all four resolve to "use an existing
// capability via a documented convention" — no upstream change was needed.
//
//  1. Structured evidence locators on claims.Source (file+line, query+
//     window) vs. free-text.
//     RESOLVED — no upstream change. TMS's own ir.Evidence/EvidenceLocator
//     (ir/evidence.go) is already the structured, typed locator (file,
//     document, config, query, url variants). structured-evaluation's
//     claims.InternalValidation.EvidencePath is free-text by design (it
//     locates evidence *within the document being evaluated*, not within
//     an arbitrary external artifact). The convention: when a Finding's
//     evidence needs to appear in a claims.Claim, cite the ir.Evidence ID
//     and Summary as the free-text EvidencePath/QuotedText — the
//     authoritative structured locator stays in the ThreatModel, addressable
//     by ID, exactly as the TRD's "else" branch anticipated.
//
//  2. An explicit "insufficient-evidence" verdict on claims/rubric.
//     RESOLVED — no upstream change. claims.VerdictNeedsReview already
//     means "a judge could not confirm this claim without further review" —
//     semantically identical to ir.FindingStatusInsufficientEvidence. See
//     FindingStatusToVerdict below for the mapping.
//
//  3. Stage/profile metadata on the report envelope.
//     RESOLVED — no upstream change. rubric.Rubric.ReviewType ("identifies
//     the type of review") is the intended carrier: a stage-specific rubric
//     review IS a type of review. Convention: ReviewType is set to the
//     ir.Stage value. See StageReviewType below.
//
//  4. Multi-judge disagreement representation.
//     CONFIRMED GAP — no equivalent exists. combine.AggregateResults /
//     AggregateWithDAG aggregate *different* agents' results into one
//     summary; they do not represent several judges independently scoring
//     the *same* subject and surfacing the spread. Per the TRD's rule
//     ("prefer conventions over upstream changes; any upstream change must
//     be additive and land before the TMS feature that needs it"), this is
//     deliberately deferred: no Phase 1 code needs it, and Phase 2/3 rubric
//     and gate work (RMI-108, RMI-109) is the first consumer. Building it
//     now would be speculative. Tracked for revisit when RMI-108 lands.
package evaluation

import (
	"github.com/plexusone/structured-evaluation/claims"

	"github.com/grokify/threat-model-spec/ir"
)

// StageReviewType returns the rubric.Rubric.ReviewType value for a
// stage-specific evaluation, per gap-assessment resolution #3.
func StageReviewType(stage ir.Stage) string {
	return string(stage)
}

// FindingStatusToVerdict maps an ir.Finding's adjudication status onto the
// structured-evaluation claims.Verdict vocabulary, per gap-assessment
// resolution #2. FindingStatusCandidate has no claims.Verdict equivalent
// (claims.Verdict describes a completed judgment; "candidate" means no
// judgment has been made yet) — callers should not invoke this before a
// judge has run.
func FindingStatusToVerdict(status ir.FindingStatus) (claims.Verdict, bool) {
	switch status {
	case ir.FindingStatusValidated:
		return claims.VerdictVerified, true
	case ir.FindingStatusRejected:
		return claims.VerdictRejected, true
	case ir.FindingStatusInsufficientEvidence:
		return claims.VerdictNeedsReview, true
	default:
		return "", false
	}
}

// VerdictToFindingStatus is the inverse of FindingStatusToVerdict, for
// converting a structured-evaluation judge's claims.Verdict back into an
// ir.Finding's Status after grading.
func VerdictToFindingStatus(v claims.Verdict) (ir.FindingStatus, bool) {
	switch v {
	case claims.VerdictVerified:
		return ir.FindingStatusValidated, true
	case claims.VerdictRejected:
		return ir.FindingStatusRejected, true
	case claims.VerdictNeedsReview:
		return ir.FindingStatusInsufficientEvidence, true
	case claims.VerdictUnverified:
		// Unverified means no validation was attempted, distinct from a
		// judge actively finding the evidence insufficient. Leave the
		// Finding at its current status rather than force a mapping.
		return "", false
	default:
		return "", false
	}
}
