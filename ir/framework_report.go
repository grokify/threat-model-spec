package ir

import "github.com/invopop/jsonschema"

// FrameworkID identifies which security framework a FrameworkReport covers.
type FrameworkID string

const (
	FrameworkSTRIDE      FrameworkID = "stride"
	FrameworkLINDDUN     FrameworkID = "linddun"
	FrameworkMITREAttack FrameworkID = "mitre-attack"
	FrameworkOWASP       FrameworkID = "owasp"
	FrameworkAttackTree  FrameworkID = "attack-tree"
)

// JSONSchema implements jsonschema.JSONSchemaer for FrameworkID.
func (FrameworkID) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"stride", "linddun", "mitre-attack", "owasp", "attack-tree"},
	}
}

// FrameworkReport is a computed, framework-specific view derived from the
// canonical ThreatModel — coverage and analysis a reader would otherwise
// have to reconstruct by hand from Mappings, DetectionCoverage, and diagram
// data scattered across the model. Computed-first: `tms report --framework
// <id>` derives one on demand from ComputeFrameworkReport; storing the
// result back on ThreatModel.FrameworkReports is optional, for an audit
// snapshot at a point in time (see SourceRevision).
//
// Exactly one of the typed Body fields is populated, matching Framework —
// named optional fields rather than an `any` Body, so the JSON Schema
// generated from this type stays concrete instead of degrading to
// unconstrained `object` for every report regardless of framework.
type FrameworkReport struct {
	// ID is the unique identifier for this report.
	ID string `json:"id"`

	// Framework identifies which framework this report covers, and which
	// of the Body fields below is populated.
	Framework FrameworkID `json:"framework"`

	// GeneratedAt is when this report was computed (RFC 3339).
	GeneratedAt string `json:"generatedAt,omitempty"`

	// SourceRevision is a content digest of the model data this report was
	// derived from, in the same bare-string convention as
	// Artifact.Digest/Evidence.Digest. tms validate compares a freshly
	// computed digest against this value to warn when a materialized
	// report has drifted from the model it was derived from.
	SourceRevision string `json:"sourceRevision,omitempty"`

	// STRIDE is populated when Framework == FrameworkSTRIDE.
	STRIDE *STRIDEReportBody `json:"strideBody,omitempty"`

	// LINDDUN is populated when Framework == FrameworkLINDDUN.
	LINDDUN *LINDDUNReportBody `json:"linddunBody,omitempty"`

	// MITREAttack is populated when Framework == FrameworkMITREAttack.
	MITREAttack *MITREAttackReportBody `json:"mitreAttackBody,omitempty"`

	// OWASP is populated when Framework == FrameworkOWASP.
	OWASP *OWASPReportBody `json:"owaspBody,omitempty"`

	// AttackTree is populated when Framework == FrameworkAttackTree.
	AttackTree *AttackTreeReportBody `json:"attackTreeBody,omitempty"`
}

// STRIDEReportBody is the computed STRIDE coverage view: the model's raw
// STRIDE mappings, plus a per-category count and the categories with zero
// mappings — the gap a reader would otherwise have to notice by counting.
type STRIDEReportBody struct {
	// Mappings is the model's raw ir.Mappings.STRIDE list.
	Mappings []STRIDEMapping `json:"mappings"`

	// CoverageByCategory counts mappings per STRIDE category.
	CoverageByCategory map[STRIDEThreat]int `json:"coverageByCategory"`

	// CategoriesCovered lists the STRIDE categories with at least one mapping.
	CategoriesCovered []STRIDEThreat `json:"categoriesCovered"`

	// CategoriesMissing lists the STRIDE categories with zero mappings.
	CategoriesMissing []STRIDEThreat `json:"categoriesMissing"`
}

// LINDDUNReportBody is the computed LINDDUN coverage view, mirroring
// STRIDEReportBody's shape for the seven LINDDUN privacy-threat categories.
type LINDDUNReportBody struct {
	// Mappings is the model's raw ir.Mappings.LINDDUN list.
	Mappings []LINDDUNMapping `json:"mappings"`

	// CoverageByCategory counts mappings per LINDDUN category.
	CoverageByCategory map[LINDDUNThreat]int `json:"coverageByCategory"`

	// CategoriesCovered lists the LINDDUN categories with at least one mapping.
	CategoriesCovered []LINDDUNThreat `json:"categoriesCovered"`

	// CategoriesMissing lists the LINDDUN categories with zero mappings.
	CategoriesMissing []LINDDUNThreat `json:"categoriesMissing"`
}

// MITREAttackReportBody is the computed MITRE ATT&CK view: the model's
// technique mappings (what threats were identified) joined against its
// detection coverage matrix (what's actually detected), by TechniqueID —
// these are two separate lists on the model that nothing else joins.
type MITREAttackReportBody struct {
	// Mappings is the model's raw ir.Mappings.MITREAttack list.
	Mappings []MITREAttackMapping `json:"mappings"`

	// DetectionCoverage is the model's detection coverage matrix, if
	// present. Nil when the model has no DetectionCoverage — a real,
	// reportable gap rather than an error.
	DetectionCoverage *DetectionCoverageMatrix `json:"detectionCoverage,omitempty"`

	// MappedTechniquesWithoutCoverage lists technique IDs that appear in
	// Mappings but have no corresponding entry in DetectionCoverage —
	// identified threats with no recorded detection posture at all.
	MappedTechniquesWithoutCoverage []string `json:"mappedTechniquesWithoutCoverage,omitempty"`
}

// OWASPReportBody is the computed OWASP coverage view across whichever
// OWASP Top 10 lists (API/LLM/Web/Agentic) the model maps into.
type OWASPReportBody struct {
	// Mappings is the model's raw ir.Mappings.OWASP list.
	Mappings []OWASPMapping `json:"mappings"`

	// CoverageByList counts mappings per OWASP list (api, llm, web, agentic).
	CoverageByList map[OWASPCategory]int `json:"coverageByList"`
}

// AttackTreeReportBody is the computed attack-path view. When the model has
// a diagram of type "attack-tree", Tree is the literal tree structure
// authored on it. In all cases, PathAnalysis is computed by building an
// AttackGraph from SourceDiagramType (preferring an attack-chain diagram,
// then falling back to the model's first DFD) and running the existing
// all-paths/shortest-path/critical-path/reachability analysis (ir/attackpath.go).
//
// EntryPoints/Targets are not authored on diagrams today, so
// ComputeAttackTreeReport infers them heuristically: external-entity
// elements as entry points, datastore elements as targets. See
// EntryPointHeuristic for the exact rule applied.
type AttackTreeReportBody struct {
	// SourceDiagramType is the diagram type the graph/tree was derived from.
	SourceDiagramType DiagramType `json:"sourceDiagramType"`

	// EntryPointHeuristic documents how EntryPoints/Targets were inferred
	// for PathAnalysis, since diagrams don't author them explicitly.
	EntryPointHeuristic string `json:"entryPointHeuristic,omitempty"`

	// Tree is the literal attack tree, populated only when the model has
	// an attack-tree-type diagram.
	Tree *AttackTree `json:"tree,omitempty"`

	// PathAnalysis is the computed graph path analysis.
	PathAnalysis *PathAnalysisResult `json:"pathAnalysis,omitempty"`
}
