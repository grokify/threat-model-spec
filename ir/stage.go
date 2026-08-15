package ir

import "github.com/invopop/jsonschema"

// Stage identifies a PDLC (Product Development Lifecycle) stage that an
// analysis run, artifact, finding, or gate belongs to. Values match
// github.com/ProductBuildersHQ/pdlc's Stage* constants exactly — see
// TestStageMatchesPDLC, which fails the build if the two drift.
//
// Stage supersedes the coarser ModelPhase for lifecycle-aware analysis:
// ModelPhase records a single point-in-time phase for the whole model,
// while Stage is carried per AnalysisRun/Artifact/Finding/Gate so a model
// can hold evidence from multiple stages simultaneously as it accumulates
// analysis across the lifecycle. ModelPhase is deprecated in favor of
// Lifecycle.CurrentStage (see ir/lifecycle.go) but retained for backward
// compatibility.
type Stage string

const (
	// StageProductDefinition is the product person's discovery-through-
	// baseline-handoff stage (pdlc.StageProductDefinition).
	StageProductDefinition Stage = "product-definition"

	// StageBuilderDefinition is the builder person's technical design stage:
	// requirements, architecture, and the finalized API contract
	// (pdlc.StageBuilderDefinition).
	StageBuilderDefinition Stage = "builder-definition"

	// StageImplementation is where code is written against the Builder
	// Definition contract. ASPM domains 1-5 (git posture, code security,
	// secret/PII scan, open source security, SBOM) overlay this stage
	// (pdlc.StageImplementation).
	StageImplementation Stage = "implementation"

	// StageDeployment is where built artifacts are released to target
	// environments. ASPM domains 6-9 (IaC scan, CI/CD posture, container
	// security, artifact security) overlay this stage
	// (pdlc.StageDeployment).
	StageDeployment Stage = "deployment"

	// StageBuilderOperations is infrastructure, security, and reliability
	// operations for the deployed system. ASPM domain 10 (cloud context)
	// plus dynamic testing (DAST, penetration testing, red teaming) overlay
	// this stage. Runs in parallel with StageProductOperations, not
	// sequentially after it (pdlc.StageBuilderOperations).
	StageBuilderOperations Stage = "builder-operations"

	// StageProductOperations is adoption, usage, and feedback operations
	// for the shipped product, feeding the next Product Definition baseline
	// revision. Runs in parallel with StageBuilderOperations
	// (pdlc.StageProductOperations).
	StageProductOperations Stage = "product-operations"
)

// JSONSchema implements jsonschema.JSONSchemaer for Stage.
func (Stage) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"product-definition",
			"builder-definition",
			"implementation",
			"deployment",
			"builder-operations",
			"product-operations",
		},
	}
}

// IsBuilderStage reports whether the stage is builder-owned (as opposed to
// product-owned). The three builder-side stages that carry an ASPM overlay
// are Implementation, Deployment, and Builder Operations.
func (s Stage) IsBuilderStage() bool {
	switch s {
	case StageBuilderDefinition, StageImplementation, StageDeployment, StageBuilderOperations:
		return true
	default:
		return false
	}
}

// AllStages returns all six Stage values in pdlc's canonical order.
func AllStages() []Stage {
	return []Stage{
		StageProductDefinition,
		StageBuilderDefinition,
		StageImplementation,
		StageDeployment,
		StageBuilderOperations,
		StageProductOperations,
	}
}
