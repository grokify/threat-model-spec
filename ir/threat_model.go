package ir

import "fmt"

// ThreatModel is the canonical representation of a security threat model.
// It contains shared metadata and framework mappings, with multiple diagram
// views of the same vulnerability or threat scenario.
//
// This is the preferred format for complete threat models. Individual DiagramIR
// files can be used for single-diagram use cases or generated from a ThreatModel.
type ThreatModel struct {
	// ID is a unique identifier for the threat model (e.g., "openclaw-websocket-localhost").
	ID string `json:"id"`

	// Title is the human-readable title of the threat model.
	Title string `json:"title"`

	// Description provides an overview of the vulnerability or threat scenario.
	Description string `json:"description,omitempty"`

	// Version tracks the threat model version (e.g., "1.0.0").
	Version string `json:"version,omitempty"`

	// Phase indicates the SDLC phase of this threat model.
	// Use "design" for pre-implementation threat modeling,
	// "production" for live systems, "incident" for post-incident analysis.
	Phase ModelPhase `json:"phase,omitempty"`

	// Authors lists the people who created or contributed to this threat model.
	Authors []Author `json:"authors,omitempty"`

	// References contains external links to related resources.
	References []Reference `json:"references,omitempty"`

	// Mappings contains references to external security frameworks
	// (MITRE ATT&CK, ATLAS, OWASP, CWE, CVSS, STRIDE).
	// These mappings apply to the overall threat model.
	Mappings *Mappings `json:"mappings,omitempty"`

	// Diagrams contains the individual diagram views of the threat model.
	// Each diagram represents a different perspective (DFD, attack chain, sequence).
	Diagrams []DiagramView `json:"diagrams"`

	// --- Enhanced threat modeling fields ---

	// ThreatActors contains adversary profiles relevant to this threat model.
	ThreatActors []ThreatActor `json:"threatActors,omitempty"`

	// Assumptions contains security assumptions underlying the threat model.
	Assumptions []Assumption `json:"assumptions,omitempty"`

	// Prerequisites contains preconditions that must be true.
	Prerequisites []Prerequisite `json:"prerequisites,omitempty"`

	// Mitigations contains countermeasures at the threat model level.
	// These apply across all diagrams; individual diagrams may have additional mitigations.
	Mitigations []Mitigation `json:"mitigations,omitempty"`

	// Assets lists the assets being protected in this threat model.
	Assets []Asset `json:"assets,omitempty"`

	// Scenarios contains what-if attack scenarios for analysis.
	Scenarios []Scenario `json:"scenarios,omitempty"`

	// --- Role-based security guidance ---

	// RedTeam contains offensive security/penetration testing guidance.
	RedTeam *ExploitationGuidance `json:"redTeam,omitempty"`

	// BlueTeam contains defensive security/detection guidance.
	BlueTeam *DefenseGuidance `json:"blueTeam,omitempty"`

	// Remediation contains developer guidance for fixing vulnerabilities.
	Remediation *RemediationGuidance `json:"remediation,omitempty"`

	// Playbooks contains incident response playbooks.
	Playbooks []IncidentPlaybook `json:"playbooks,omitempty"`

	// TestSuites links to app-test-spec test suites for validation.
	TestSuites []TestSuiteReference `json:"testSuites,omitempty"`

	// --- Risk quantification ---

	// RiskAssessment contains FAIR (Factor Analysis of Information Risk) assessment data.
	RiskAssessment *FAIRAssessment `json:"riskAssessment,omitempty"`

	// BusinessImpact contains broader business impact analysis.
	BusinessImpact *BusinessImpact `json:"businessImpact,omitempty"`

	// EPSSData contains Exploit Prediction Scoring System data for CVEs.
	EPSSData []EPSSData `json:"epssData,omitempty"`

	// --- Purple Team (Adversary Emulation) ---

	// AtomicTests contains Atomic Red Team test mappings for validation.
	AtomicTests []AtomicTestMapping `json:"atomicTests,omitempty"`

	// DetectionCoverage contains MITRE ATT&CK detection coverage matrix.
	DetectionCoverage *DetectionCoverageMatrix `json:"detectionCoverage,omitempty"`

	// --- Security Metrics ---

	// Metrics contains security metrics for tracking detection/response effectiveness.
	Metrics *SecurityMetrics `json:"metrics,omitempty"`

	// --- Supply Chain Security ---

	// SBOM contains references to Software Bill of Materials documents.
	SBOM *SBOMReference `json:"sbom,omitempty"`

	// VEXStatements contains Vulnerability Exploitability eXchange statements.
	VEXStatements []VEXStatement `json:"vexStatements,omitempty"`

	// DependencyRisks tracks risk information for software dependencies.
	DependencyRisks []DependencyRisk `json:"dependencyRisks,omitempty"`
}

// Author represents a contributor to the threat model.
type Author struct {
	// Name is the author's name.
	Name string `json:"name"`

	// Email is the author's email address.
	Email string `json:"email,omitempty"`

	// URL is a link to the author's profile or website.
	URL string `json:"url,omitempty"`
}

// Reference is an external resource related to the threat model.
type Reference struct {
	// Title is the reference title.
	Title string `json:"title"`

	// URL is the link to the resource.
	URL string `json:"url"`

	// Type categorizes the reference (e.g., "advisory", "blog", "paper", "cve").
	Type string `json:"type,omitempty"`
}

// DiagramView represents a single diagram within a ThreatModel.
// It embeds DiagramIR but allows the diagram to inherit or override
// the parent ThreatModel's mappings.
type DiagramView struct {
	// Type identifies the diagram type (dfd, attack-chain, sequence).
	Type DiagramType `json:"type"`

	// Title is the diagram-specific title. If empty, inherits from ThreatModel.
	Title string `json:"title,omitempty"`

	// Description provides diagram-specific context.
	Description string `json:"description,omitempty"`

	// Direction specifies the layout direction (right, down, etc.).
	Direction Direction `json:"direction,omitempty"`

	// Legend controls whether to show the legend.
	Legend *Legend `json:"legend,omitempty"`

	// Mappings contains diagram-specific framework mappings.
	// If nil, the diagram inherits from the parent ThreatModel.
	// If set, these mappings apply only to this diagram view.
	Mappings *Mappings `json:"mappings,omitempty"`

	// --- DFD and Attack Chain fields ---

	// Elements are the DFD elements (processes, datastores, external entities).
	Elements []Element `json:"elements,omitempty"`

	// Boundaries are the trust boundaries containing elements.
	Boundaries []Boundary `json:"boundaries,omitempty"`

	// Flows are the data flows between elements (for DFD).
	Flows []Flow `json:"flows,omitempty"`

	// --- Attack Chain specific fields ---

	// Attacks are the attack steps (for attack-chain type).
	Attacks []Attack `json:"attacks,omitempty"`

	// Targets are the high-value assets being targeted.
	Targets []Target `json:"targets,omitempty"`

	// --- Sequence diagram specific fields ---

	// Actors are the lifelines in a sequence diagram.
	Actors []Actor `json:"actors,omitempty"`

	// Phases group messages into logical attack phases.
	Phases []Phase `json:"phases,omitempty"`

	// Messages are the interactions between actors (for sequence type).
	Messages []Message `json:"messages,omitempty"`

	// --- Attack Tree specific fields ---

	// AttackTree contains the attack tree structure for attack-tree type.
	AttackTree *AttackTree `json:"attackTree,omitempty"`

	// --- Cross-cutting security fields ---

	// Threats contains identified threats with status tracking.
	Threats []ThreatEntry `json:"threats,omitempty"`

	// Mitigations contains countermeasures addressing identified threats.
	Mitigations []Mitigation `json:"mitigations,omitempty"`

	// Detections contains detection capabilities for threats and attacks.
	Detections []Detection `json:"detections,omitempty"`

	// ResponseActions contains incident response actions.
	ResponseActions []ResponseAction `json:"responseActions,omitempty"`
}

// ToDigramIR converts a DiagramView to a standalone DiagramIR,
// inheriting mappings from the parent ThreatModel if not overridden.
func (dv *DiagramView) ToDiagramIR(parent *ThreatModel) *DiagramIR {
	ir := &DiagramIR{
		Type:            dv.Type,
		Title:           dv.Title,
		Description:     dv.Description,
		Direction:       dv.Direction,
		Legend:          dv.Legend,
		Mappings:        dv.Mappings,
		Elements:        dv.Elements,
		Boundaries:      dv.Boundaries,
		Flows:           dv.Flows,
		Attacks:         dv.Attacks,
		Targets:         dv.Targets,
		Actors:          dv.Actors,
		Phases:          dv.Phases,
		Messages:        dv.Messages,
		AttackTree:      dv.AttackTree,
		Threats:         dv.Threats,
		Mitigations:     dv.Mitigations,
		Detections:      dv.Detections,
		ResponseActions: dv.ResponseActions,
	}

	// Inherit title from parent if not set
	if ir.Title == "" && parent != nil {
		ir.Title = parent.Title
	}

	// Inherit mappings from parent if not set
	if ir.Mappings == nil && parent != nil {
		ir.Mappings = parent.Mappings
	}

	// Inherit mitigations from parent if not set at diagram level
	if len(ir.Mitigations) == 0 && parent != nil && len(parent.Mitigations) > 0 {
		ir.Mitigations = parent.Mitigations
	}

	return ir
}

// GetDiagram returns the first diagram of the specified type, or nil if not found.
func (tm *ThreatModel) GetDiagram(dt DiagramType) *DiagramView {
	for i := range tm.Diagrams {
		if tm.Diagrams[i].Type == dt {
			return &tm.Diagrams[i]
		}
	}
	return nil
}

// GetDiagramIR returns a standalone DiagramIR for the specified type,
// with inherited mappings from the ThreatModel.
func (tm *ThreatModel) GetDiagramIR(dt DiagramType) *DiagramIR {
	dv := tm.GetDiagram(dt)
	if dv == nil {
		return nil
	}
	return dv.ToDiagramIR(tm)
}

// Validate checks that the ThreatModel is internally consistent.
func (tm *ThreatModel) Validate() error {
	var errs ValidationErrors

	// Check required fields
	if tm.ID == "" {
		errs = append(errs, ValidationError{"id", "required"})
	}
	if tm.Title == "" {
		errs = append(errs, ValidationError{"title", "required"})
	}
	if len(tm.Diagrams) == 0 {
		errs = append(errs, ValidationError{"diagrams", "requires at least one diagram"})
	}

	// Validate each diagram
	for i, dv := range tm.Diagrams {
		// Convert to DiagramIR for validation (with inherited mappings)
		d := dv.ToDiagramIR(tm)
		if err := d.Validate(); err != nil {
			if verrs, ok := err.(ValidationErrors); ok {
				for _, e := range verrs {
					errs = append(errs, ValidationError{
						Field:   fmt.Sprintf("diagrams[%d].%s", i, e.Field),
						Message: e.Message,
					})
				}
			} else {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("diagrams[%d]", i),
					Message: err.Error(),
				})
			}
		}
	}

	if errs.HasErrors() {
		return errs
	}
	return nil
}

// IsValid returns true if the threat model passes validation.
func (tm *ThreatModel) IsValid() bool {
	return tm.Validate() == nil
}
