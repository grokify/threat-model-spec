package ir

import "github.com/invopop/jsonschema"

// StageInputMode identifies how a StageReportProfile's inputs are resolved.
type StageInputMode string

const (
	// StageInputModeWorkflowSpecs means inputs are all specs a workflow
	// categorizes into this PDLC stage (the two spec-driven stages:
	// Product Definition, Builder Definition), resolved via the
	// specification-workflow-spec registry — the profile declares no
	// spec-type list of its own.
	StageInputModeWorkflowSpecs StageInputMode = "workflow-specs"

	// StageInputModeArtifactTypes means inputs are non-spec artifacts by
	// type (the builder-side stages: Implementation, Deployment, Builder
	// Operations, Product Operations), enumerated in ArtifactTypes.
	StageInputModeArtifactTypes StageInputMode = "artifact-types"
)

// JSONSchema implements jsonschema.JSONSchemaer for StageInputMode.
func (StageInputMode) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"workflow-specs", "artifact-types"},
	}
}

// StageReportProfile is the normative definition of what a stage analysis
// report contains: how its inputs are resolved, which IR object types it
// must populate, the deterministic completeness checks it must pass, and
// the rubric it is graded against. One profile exists per PDLC stage.
type StageReportProfile struct {
	// Stage is the PDLC stage this profile defines.
	Stage Stage `json:"stage"`

	// InputMode determines how inputs are resolved for this stage.
	InputMode StageInputMode `json:"inputMode"`

	// ArtifactTypes enumerates the artifact types this stage consumes.
	// Populated only when InputMode is StageInputModeArtifactTypes.
	ArtifactTypes []ArtifactType `json:"artifactTypes,omitempty"`

	// ASPMDomainIDs lists the ASPM domains this stage's report organizes
	// findings by. Populated only for the three builder-side stages that
	// carry an ASPM overlay (Implementation, Deployment, Builder
	// Operations).
	ASPMDomainIDs []ASPMDomainID `json:"aspmDomainIds,omitempty"`

	// OutputObjects lists the IR object type names a compliant report for
	// this stage must populate (e.g. "SecurityRequirement", "Finding").
	OutputObjects []string `json:"outputObjects"`

	// CoverageChecks lists deterministic completeness check identifiers
	// evaluated against a report for this stage (e.g.
	// "all-aspm-domains-covered").
	CoverageChecks []string `json:"coverageChecks"`

	// RubricID references the structured-evaluation rubric this stage's
	// reports are graded against.
	RubricID string `json:"rubricId"`
}
