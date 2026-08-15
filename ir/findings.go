package ir

import "github.com/invopop/jsonschema"

// FindingType categorizes an analyzer's claim.
type FindingType string

const (
	// FindingTypeObservation is a near-direct fact extracted from an
	// artifact, carried at high confidence. Observation is deliberately
	// not a separate object type from Finding — see the Finding doc.
	FindingTypeObservation FindingType = "observation"

	// FindingTypeThreatCandidate is a hypothesized threat requiring
	// adjudication before promotion to a Scenario.
	FindingTypeThreatCandidate FindingType = "threat-candidate"

	// FindingTypeVulnerability is an observed weakness that enables a
	// threat.
	FindingTypeVulnerability FindingType = "vulnerability"

	// FindingTypeWeakness is a general security weakness not yet tied to a
	// specific exploitable threat.
	FindingTypeWeakness FindingType = "weakness"

	// FindingTypeDrift is a design-vs-implementation or design-vs-deployed
	// divergence.
	FindingTypeDrift FindingType = "drift"

	// FindingTypeControlGap is a missing or ineffective control.
	FindingTypeControlGap FindingType = "control-gap"
)

// JSONSchema implements jsonschema.JSONSchemaer for FindingType.
func (FindingType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"observation", "threat-candidate", "vulnerability", "weakness", "drift", "control-gap"},
	}
}

// FindingStatus tracks a Finding through adjudication.
type FindingStatus string

const (
	// FindingStatusCandidate is the initial state: proposed, not yet judged.
	FindingStatusCandidate FindingStatus = "candidate"

	// FindingStatusValidated means the finding was confirmed by a judge or
	// human reviewer.
	FindingStatusValidated FindingStatus = "validated"

	// FindingStatusRejected means the finding was determined to be
	// incorrect or not applicable.
	FindingStatusRejected FindingStatus = "rejected"

	// FindingStatusInsufficientEvidence means a judge could not confirm or
	// reject the finding given the available evidence — an explicit
	// abstention rather than a forced accept/reject.
	FindingStatusInsufficientEvidence FindingStatus = "insufficient-evidence"
)

// JSONSchema implements jsonschema.JSONSchemaer for FindingStatus.
func (FindingStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"candidate", "validated", "rejected", "insufficient-evidence"},
	}
}

// Finding is an analyzer's claim requiring adjudication: a threat
// candidate, vulnerability, weakness, drift assertion, or control gap.
// Near-direct facts are recorded as findings with Type ==
// FindingTypeObservation and Confidence near 1.0, rather than as a separate
// Observation object — this keeps the IR's claim vocabulary to one object
// type instead of splitting "raw fact" and "interpretation" into two
// parallel structures that would otherwise need to cross-reference each
// other for every claim.
//
// A validated FindingTypeThreatCandidate finding may be promoted to a
// Scenario by a synthesis step; PromotedToID records the resulting
// Scenario ID. Existing Scenario/threat objects are otherwise unchanged by
// this type.
type Finding struct {
	// ID is the unique identifier for this finding.
	ID string `json:"id"`

	// Type categorizes the claim.
	Type FindingType `json:"type"`

	// Stage is the PDLC stage this finding was produced at.
	Stage Stage `json:"stage,omitempty"`

	// Title is a brief summary of the finding.
	Title string `json:"title"`

	// Description provides detailed explanation.
	Description string `json:"description,omitempty"`

	// TargetRefs references the affected component/element/asset IDs.
	TargetRefs []string `json:"targetRefs,omitempty"`

	// EvidenceIDs references the Evidence supporting this finding.
	EvidenceIDs []string `json:"evidenceIds,omitempty"`

	// Confidence is the producer's confidence in this finding (0.0-1.0).
	Confidence float64 `json:"confidence,omitempty"`

	// Status tracks this finding through adjudication.
	Status FindingStatus `json:"status"`

	// ASPMDomainID tags a builder-stage finding with its ASPM domain, when
	// applicable.
	ASPMDomainID ASPMDomainID `json:"aspmDomainId,omitempty"`

	// ProducerRunID references the AnalysisRun that produced this finding.
	ProducerRunID string `json:"producerRunId,omitempty"`

	// PromotedToID references the Scenario this finding was promoted to,
	// once validated and synthesized.
	PromotedToID string `json:"promotedToId,omitempty"`
}

// SecurityRequirementType categorizes a security requirement derived from
// product-definition-stage analysis.
type SecurityRequirementType string

const (
	SecurityRequirementTypeInvariant         SecurityRequirementType = "invariant"
	SecurityRequirementTypeProhibitedOutcome SecurityRequirementType = "prohibited-outcome"
	SecurityRequirementTypePrivacy           SecurityRequirementType = "privacy-requirement"
	SecurityRequirementTypeApproval          SecurityRequirementType = "approval-requirement"
	SecurityRequirementTypeRecovery          SecurityRequirementType = "recovery-requirement"
	SecurityRequirementTypeDetection         SecurityRequirementType = "detection-requirement"
)

// JSONSchema implements jsonschema.JSONSchemaer for SecurityRequirementType.
func (SecurityRequirementType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"invariant", "prohibited-outcome", "privacy-requirement",
			"approval-requirement", "recovery-requirement", "detection-requirement",
		},
	}
}

// SecurityRequirement is an invariant or prohibited outcome derived from
// product-definition-stage analysis (e.g. "a principal can access resources
// only within its tenant"), with links to the artifact it originated from
// and the gates/runs that verify it.
type SecurityRequirement struct {
	// ID is the unique identifier for this requirement.
	ID string `json:"id"`

	// Statement is the requirement in plain language.
	Statement string `json:"statement"`

	// Type categorizes the requirement.
	Type SecurityRequirementType `json:"type"`

	// Criticality indicates impact if violated: critical, high, medium, or low.
	Criticality string `json:"criticality,omitempty"`

	// OriginArtifactID references the Artifact this requirement was derived from.
	OriginArtifactID string `json:"originArtifactId,omitempty"`

	// VerificationIDs references the AnalysisRun or Gate IDs that verify this requirement.
	VerificationIDs []string `json:"verificationIds,omitempty"`
}

// ArchitectureAssertionStatus indicates whether observed reality supports
// or contradicts the intended design.
type ArchitectureAssertionStatus string

const (
	ArchitectureAssertionStatusSupported    ArchitectureAssertionStatus = "supported"
	ArchitectureAssertionStatusContradicted ArchitectureAssertionStatus = "contradicted"
	ArchitectureAssertionStatusUnverified   ArchitectureAssertionStatus = "unverified"
)

// JSONSchema implements jsonschema.JSONSchemaer for ArchitectureAssertionStatus.
func (ArchitectureAssertionStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"supported", "contradicted", "unverified"},
	}
}

// ArchitectureAssertion captures an intended-vs-observed property for drift
// detection: what the design required (Expected), what was actually
// observed (Observed), and whether the two agree (Status). This is the
// object that lets an agent express claims like "the tech spec requires a
// private administrative API, but the deployment manifest exposes it
// publicly" without later implementation facts silently overwriting design
// assumptions.
type ArchitectureAssertion struct {
	// ID is the unique identifier for this assertion.
	ID string `json:"id"`

	// SubjectID references the component/element this assertion is about.
	SubjectID string `json:"subjectId"`

	// Predicate names the property being asserted (e.g. "network-exposure").
	Predicate string `json:"predicate"`

	// Expected is the value the design requires.
	Expected string `json:"expected"`

	// Observed is the value actually observed, once implementation or
	// deployment evidence exists.
	Observed string `json:"observed,omitempty"`

	// ExpectedEvidenceIDs references the Evidence supporting Expected.
	ExpectedEvidenceIDs []string `json:"expectedEvidenceIds,omitempty"`

	// ObservedEvidenceIDs references the Evidence supporting Observed.
	ObservedEvidenceIDs []string `json:"observedEvidenceIds,omitempty"`

	// Status indicates whether Observed agrees with Expected.
	Status ArchitectureAssertionStatus `json:"status"`
}
