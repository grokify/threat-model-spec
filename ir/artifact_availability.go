package ir

// StageScopeNote records why a stage cannot be credibly analyzed under a
// given ArtifactAvailabilityProfile. Reports produced under a partial
// profile should state these explicitly, so an absence of findings for an
// unanalyzable stage is never misread as an absence of risk.
type StageScopeNote struct {
	// Stage is the PDLC stage that cannot be analyzed.
	Stage Stage `json:"stage"`

	// Reason explains why, in one sentence.
	Reason string `json:"reason"`
}

// ArtifactAvailabilityProfile declares which artifact types are typically
// available for an analysis target under a given profile, and which PDLC
// stages that availability permits analyzing. AnalysisRun.Profile records
// which profile governed a given run, so every report is traceable to the
// evidence basis it was produced under.
//
// Three profiles are defined: first-party (all artifacts, all stages),
// third-party (public docs + a live site — no source, no internal specs),
// and open-source (docs + source code — no deployment/operations
// visibility). A profile is a default expectation, not a hard constraint:
// an analysis run may still find more or fewer artifacts than its profile
// typically implies.
type ArtifactAvailabilityProfile struct {
	// Profile identifies which of the three profiles this is.
	Profile AnalysisRunProfile `json:"profile"`

	// Description explains the profile's evidence basis in plain language.
	Description string `json:"description,omitempty"`

	// AvailableArtifactTypes lists the artifact types typically available
	// under this profile.
	AvailableArtifactTypes []ArtifactType `json:"availableArtifactTypes,omitempty"`

	// PermittedStages lists the PDLC stages that can be credibly analyzed
	// given this profile's typical artifact availability.
	PermittedStages []Stage `json:"permittedStages"`

	// NotAnalyzableStages lists stages this profile cannot credibly cover,
	// with a reason for each — the explicit "what was not analyzable"
	// statement a partial-profile report must carry.
	NotAnalyzableStages []StageScopeNote `json:"notAnalyzableStages,omitempty"`
}

// PermitsStage reports whether this profile permits analyzing the given
// stage.
func (p ArtifactAvailabilityProfile) PermitsStage(stage Stage) bool {
	for _, s := range p.PermittedStages {
		if s == stage {
			return true
		}
	}
	return false
}
