package ir

// AnalysisResults is the output-object contract an analysis agent returns
// after reasoning about a stage: the bundle of lifecycle objects a `tms
// analyze --apply` call merges into the model under the AnalysisRun that
// requested them. Only the object types relevant to a given stage need be
// populated — see StageReportProfile.OutputObjects for which apply per
// stage.
type AnalysisResults struct {
	// Findings are the analyzer's claims for this run.
	Findings []Finding `json:"findings,omitempty"`

	// Evidence supports the Findings/Assertions/Requirements in this bundle.
	Evidence []Evidence `json:"evidence,omitempty"`

	// ArchitectureAssertions record intended-vs-observed checks made during
	// this run.
	ArchitectureAssertions []ArchitectureAssertion `json:"architectureAssertions,omitempty"`

	// SecurityRequirements are invariants/prohibited-outcomes derived
	// during this run (typically Product Definition only).
	SecurityRequirements []SecurityRequirement `json:"securityRequirements,omitempty"`

	// Assets are valuable resources identified during this run (typically
	// Product Definition only).
	Assets []Asset `json:"assets,omitempty"`

	// ThreatActors are adversary profiles identified during this run
	// (typically Product Definition only).
	ThreatActors []ThreatActor `json:"threatActors,omitempty"`

	// Scenarios are abuse-case scenarios identified during this run
	// (typically Product Definition only).
	Scenarios []Scenario `json:"scenarios,omitempty"`

	// Mitigations are countermeasures identified during this run
	// (typically Builder Definition only).
	Mitigations []Mitigation `json:"mitigations,omitempty"`
}
