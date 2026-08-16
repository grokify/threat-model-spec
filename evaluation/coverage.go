package evaluation

import "github.com/grokify/threat-model-spec/ir"

// ComputeCoverageChecks evaluates every coverage check ID in stage's
// StageReportProfile that is deterministically computable from model,
// returning results for those checks plus the IDs of checks that remain
// the caller's responsibility to supply — e.g. has-trust-boundaries, which
// requires interpreting a diagram the IR does not itself formalize.
//
// A check ID this function knows how to compute always wins over any
// caller-supplied value for the same ID: callers should treat the returned
// results as authoritative and only fill in the returned uncomputed IDs.
func ComputeCoverageChecks(model *ir.ThreatModel, stage ir.Stage) (CoverageCheckResults, []string, error) {
	profile, err := ir.StageReportProfileByStage(stage)
	if err != nil {
		return nil, nil, err
	}

	results := make(CoverageCheckResults, len(profile.CoverageChecks))
	var uncomputed []string
	for _, checkID := range profile.CoverageChecks {
		passed, ok := computeCoverageCheck(model, stage, checkID)
		if !ok {
			uncomputed = append(uncomputed, checkID)
			continue
		}
		results[checkID] = passed
	}
	return results, uncomputed, nil
}

// computeCoverageCheck evaluates a single check ID deterministically from
// model. ok is false when this check is not one ComputeCoverageChecks knows
// how to derive from the IR alone.
func computeCoverageCheck(model *ir.ThreatModel, stage ir.Stage, checkID string) (passed bool, ok bool) {
	switch checkID {
	case "has-stride-mapping":
		return hasSTRIDEMappedThreatCandidates(model, stage), true
	case "has-prohibited-outcome":
		return hasSecurityRequirementType(model, ir.SecurityRequirementTypeProhibitedOutcome), true
	case "has-invariant":
		return hasSecurityRequirementType(model, ir.SecurityRequirementTypeInvariant), true
	case "has-assets":
		return len(model.Assets) > 0, true
	case "has-threat-actor":
		return len(model.ThreatActors) > 0, true
	case "has-evidence-per-finding":
		return hasEvidencePerFinding(model, stage), true
	default:
		return false, false
	}
}

// hasSTRIDEMappedThreatCandidates reports whether every threat-candidate
// Finding at stage carries at least one STRIDE category, and whether at
// least one such Finding exists — an empty set does not count as covered.
func hasSTRIDEMappedThreatCandidates(model *ir.ThreatModel, stage ir.Stage) bool {
	found := false
	for _, f := range model.Findings {
		if f.Stage != stage || f.Type != ir.FindingTypeThreatCandidate {
			continue
		}
		found = true
		if len(f.STRIDEThreats) == 0 {
			return false
		}
	}
	return found
}

// hasSecurityRequirementType reports whether the model has at least one
// SecurityRequirement of the given type.
func hasSecurityRequirementType(model *ir.ThreatModel, t ir.SecurityRequirementType) bool {
	for _, r := range model.SecurityRequirements {
		if r.Type == t {
			return true
		}
	}
	return false
}

// hasEvidencePerFinding reports whether every Finding at stage carries at
// least one EvidenceIDs entry that resolves to real Evidence, and whether
// at least one such Finding exists — an empty set does not count as covered.
func hasEvidencePerFinding(model *ir.ThreatModel, stage ir.Stage) bool {
	evidenceIDs := make(map[string]bool, len(model.Evidence))
	for _, e := range model.Evidence {
		evidenceIDs[e.ID] = true
	}

	found := false
	for _, f := range model.Findings {
		if f.Stage != stage {
			continue
		}
		found = true
		if len(f.EvidenceIDs) == 0 {
			return false
		}
		for _, eid := range f.EvidenceIDs {
			if !evidenceIDs[eid] {
				return false
			}
		}
	}
	return found
}
