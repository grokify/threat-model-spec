package ir

import "github.com/invopop/jsonschema"

// ArtifactType categorizes an analyzed input artifact by what kind of
// source material it is.
type ArtifactType string

const (
	ArtifactTypeProductSpec         ArtifactType = "product-spec"
	ArtifactTypeTechnicalSpec       ArtifactType = "technical-spec"
	ArtifactTypeArchitectureDiagram ArtifactType = "architecture-diagram"
	ArtifactTypeAPISpec             ArtifactType = "api-spec"
	ArtifactTypeSourceTree          ArtifactType = "source-tree"
	ArtifactTypeDependencyManifest  ArtifactType = "dependency-manifest"
	ArtifactTypeSBOM                ArtifactType = "sbom"
	ArtifactTypeIaC                 ArtifactType = "iac"
	ArtifactTypeDeploymentManifest  ArtifactType = "deployment-manifest"
	ArtifactTypeRuntimeEndpoint     ArtifactType = "runtime-endpoint"
	ArtifactTypeTelemetry           ArtifactType = "telemetry"
	ArtifactTypeIncident            ArtifactType = "incident"
)

// JSONSchema implements jsonschema.JSONSchemaer for ArtifactType.
func (ArtifactType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"product-spec", "technical-spec", "architecture-diagram", "api-spec",
			"source-tree", "dependency-manifest", "sbom", "iac",
			"deployment-manifest", "runtime-endpoint", "telemetry", "incident",
		},
	}
}

// Artifact is a source input an AnalysisRun was performed against.
type Artifact struct {
	// ID is the unique identifier for this artifact.
	ID string `json:"id"`

	// Type categorizes the kind of artifact.
	Type ArtifactType `json:"type"`

	// URI locates the artifact (e.g. a repo-relative path or repo:// URI).
	URI string `json:"uri,omitempty"`

	// Revision identifies the specific version analyzed (e.g. a git SHA).
	Revision string `json:"revision,omitempty"`

	// Stage is the PDLC stage this artifact belongs to.
	Stage Stage `json:"stage,omitempty"`

	// Digest is a content hash of the artifact at the analyzed revision.
	Digest string `json:"digest,omitempty"`

	// ObservedAt is when this artifact was observed/collected (RFC 3339).
	ObservedAt string `json:"observedAt,omitempty"`
}

// AnalysisRunStatus tracks the lifecycle of an analysis run.
type AnalysisRunStatus string

const (
	AnalysisRunStatusInProgress AnalysisRunStatus = "in-progress"
	AnalysisRunStatusCompleted  AnalysisRunStatus = "completed"
	AnalysisRunStatusFailed     AnalysisRunStatus = "failed"
)

// JSONSchema implements jsonschema.JSONSchemaer for AnalysisRunStatus.
func (AnalysisRunStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"in-progress", "completed", "failed"},
	}
}

// AnalysisRunProfile is the artifact-availability profile that governed a
// run, determining which analyses were possible given what artifacts
// existed for the target.
type AnalysisRunProfile string

const (
	AnalysisRunProfileFirstParty AnalysisRunProfile = "first-party"
	AnalysisRunProfileThirdParty AnalysisRunProfile = "third-party"
	AnalysisRunProfileOpenSource AnalysisRunProfile = "open-source"
)

// JSONSchema implements jsonschema.JSONSchemaer for AnalysisRunProfile.
func (AnalysisRunProfile) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"first-party", "third-party", "open-source"},
	}
}

// AnalysisProducer identifies who or what performed an analysis run.
type AnalysisProducer struct {
	// Type is the kind of producer: "agent", "tool", or "human".
	Type string `json:"type"`

	// Name identifies the specific producer (e.g. an agent or tool name).
	Name string `json:"name"`

	// Version is the producer's version, for reproducibility.
	Version string `json:"version,omitempty"`
}

// AnalysisRun records who analyzed what, how, and when. Findings, Evidence,
// and Gates reference the AnalysisRun that produced them via ProducerRunID
// / EvaluatedBy, giving every claim in the model a traceable origin.
type AnalysisRun struct {
	// ID is the unique identifier for this run.
	ID string `json:"id"`

	// Stage is the PDLC stage this run analyzed.
	Stage Stage `json:"stage"`

	// Method describes the analysis method (e.g. "threat-modeling", "sast",
	// "sca", "dast", "llm-judge").
	Method string `json:"method,omitempty"`

	// Profile is the artifact-availability profile that governed this run.
	Profile AnalysisRunProfile `json:"profile,omitempty"`

	// Producer identifies who or what performed the run.
	Producer AnalysisProducer `json:"producer"`

	// InputArtifactIDs lists the Artifacts this run analyzed.
	InputArtifactIDs []string `json:"inputArtifactIds,omitempty"`

	// StartedAt is when the run began (RFC 3339).
	StartedAt string `json:"startedAt,omitempty"`

	// CompletedAt is when the run finished (RFC 3339).
	CompletedAt string `json:"completedAt,omitempty"`

	// Status is the current run status.
	Status AnalysisRunStatus `json:"status"`
}

// GateResult indicates the outcome of a stage gate evaluation.
type GateResult string

const (
	GateResultPassed  GateResult = "passed"
	GateResultFailed  GateResult = "failed"
	GateResultPending GateResult = "pending"
)

// JSONSchema implements jsonschema.JSONSchemaer for GateResult.
func (GateResult) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"passed", "failed", "pending"},
	}
}

// GateCriterion is one deterministic check contributing to a gate result.
type GateCriterion struct {
	// Metric is the criterion being checked (e.g. "unaccepted-critical-findings").
	Metric string `json:"metric"`

	// Operator is the comparison applied (e.g. "equals", "gte", "lte").
	Operator string `json:"operator"`

	// Value is the threshold or expected value being compared against.
	Value string `json:"value"`
}

// Gate records a stage-gate evaluation: the criteria checked, who or what
// evaluated them, and the result. CI/CD enforcement of gates is deliberately
// out of scope for this format — Gate records the criteria and result;
// enforcing them is the consuming pipeline's responsibility.
type Gate struct {
	// ID is the unique identifier for this gate evaluation.
	ID string `json:"id"`

	// Stage is the PDLC stage this gate evaluates.
	Stage Stage `json:"stage"`

	// Criteria lists the deterministic checks evaluated for this gate.
	Criteria []GateCriterion `json:"criteria,omitempty"`

	// Result is the gate outcome.
	Result GateResult `json:"result"`

	// EvaluatedBy identifies the evaluator (e.g. a policy engine or run ID).
	EvaluatedBy string `json:"evaluatedBy,omitempty"`

	// EvidenceIDs references the Evidence supporting this evaluation.
	EvidenceIDs []string `json:"evidenceIds,omitempty"`

	// EvaluatedAt is when this gate was evaluated (RFC 3339).
	EvaluatedAt string `json:"evaluatedAt,omitempty"`
}

// Lifecycle groups stage-tracking state for the threat model as a whole.
// CurrentStage supersedes the coarser, deprecated ModelPhase: a lifecycle-
// aware model accumulates AnalysisRuns, Findings, and Evidence from
// multiple stages simultaneously, so CurrentStage records only the most
// recently active stage, not the model's sole phase.
type Lifecycle struct {
	// CurrentStage is the PDLC stage most recently analyzed.
	CurrentStage Stage `json:"currentStage,omitempty"`
}
