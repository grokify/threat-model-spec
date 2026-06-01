package evaluation

// Severity levels following InfoSec conventions.
type Severity string

const (
	SeverityCritical Severity = "critical" // Publication blocker - must fix
	SeverityHigh     Severity = "high"     // Publication blocker - must fix
	SeverityMedium   Severity = "medium"   // Should fix, tracked
	SeverityLow      Severity = "low"      // Nice to fix
	SeverityInfo     Severity = "info"     // Informational only
)

// Category IDs for vulnerability articles.
const (
	CategoryTechnicalAccuracy     = "technical_accuracy"
	CategoryResponsibleDisclosure = "responsible_disclosure"
	CategoryCompleteness          = "completeness"
	CategoryActionability         = "actionability"
	CategoryFrameworkMappings     = "framework_mappings"
	CategorySourceAttribution     = "source_attribution"
	CategoryDetectionContent      = "detection_content"
	CategoryWritingQuality        = "writing_quality"
	CategoryDiagramQuality        = "diagram_quality"
)

// Category IDs for threat model JSON files.
const (
	CategorySchemaCompliance    = "schema_compliance"
	CategoryAssetIdentification = "asset_identification"
	CategoryAttackModeling      = "attack_modeling"
	CategoryMappingAccuracy     = "mapping_accuracy"
	CategoryMitigationQuality   = "mitigation_quality"
	CategoryDiagramIntegration  = "diagram_integration"
	CategoryThreatCoverage      = "threat_coverage"
	CategoryCredentialFlows     = "credential_flows"
	CategoryRedBlueContent      = "red_blue_content"
)

// Category IDs for diagrams.
const (
	CategoryTrustBoundaries   = "trust_boundaries"
	CategoryAttackFlowClarity = "attack_flow_clarity"
	CategoryNotationStandards = "notation_standards"
	CategoryDataFlowAccuracy  = "data_flow_accuracy"
	CategoryConsistency       = "consistency"
	CategoryRenderingQuality  = "rendering_quality"
	CategoryAccessibility     = "accessibility"
)

// FindingTemplate defines a reusable finding pattern.
type FindingTemplate struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
	Effort         string   `json:"effort"` // low, medium, high
}

// ArticleFindingsCatalog returns common findings for vulnerability articles.
func ArticleFindingsCatalog() []FindingTemplate {
	return []FindingTemplate{
		// Critical - Publication Blockers
		{
			ID:             "ART-C001",
			Category:       string(CategoryTechnicalAccuracy),
			Severity:       SeverityCritical,
			Title:          "CVE details do not match NVD/authoritative source",
			Description:    "The CVE ID, CVSS score, affected versions, or description contradicts the official CVE record.",
			Recommendation: "Verify all CVE details against NVD (nvd.nist.gov) and vendor advisory. Update to match authoritative sources.",
			Effort:         "low",
		},
		{
			ID:             "ART-C002",
			Category:       string(CategoryTechnicalAccuracy),
			Severity:       SeverityCritical,
			Title:          "Attack chain is technically implausible",
			Description:    "The described attack sequence cannot work as written due to technical impossibilities or incorrect assumptions.",
			Recommendation: "Review attack chain with subject matter expert. Test attack steps in lab environment if possible.",
			Effort:         "high",
		},
		{
			ID:             "ART-C003",
			Category:       string(CategoryResponsibleDisclosure),
			Severity:       SeverityCritical,
			Title:          "Premature disclosure before patch availability",
			Description:    "Article discloses vulnerability details before vendor has released a patch or agreed to coordinated disclosure.",
			Recommendation: "Delay publication until patch is available or coordinate with vendor on disclosure timeline.",
			Effort:         "low",
		},
		{
			ID:             "ART-C004",
			Category:       string(CategoryResponsibleDisclosure),
			Severity:       SeverityCritical,
			Title:          "Contains weaponized exploit code",
			Description:    "Article includes ready-to-use exploit code beyond what's needed for defensive understanding.",
			Recommendation: "Remove or sanitize exploit code. Focus on detection and defense rather than offense.",
			Effort:         "medium",
		},
		{
			ID:             "ART-C005",
			Category:       string(CategorySourceAttribution),
			Severity:       SeverityCritical,
			Title:          "Potential plagiarism detected",
			Description:    "Significant portions of text appear to be copied from other sources without attribution.",
			Recommendation: "Rewrite in original words or properly quote and attribute sources.",
			Effort:         "high",
		},

		// High - Must Fix Before Publication
		{
			ID:             "ART-H001",
			Category:       string(CategoryTechnicalAccuracy),
			Severity:       SeverityHigh,
			Title:          "Code examples contain syntax errors",
			Description:    "Code snippets in the article have syntax errors that would prevent them from running.",
			Recommendation: "Test all code examples. Use syntax highlighting to catch errors.",
			Effort:         "low",
		},
		{
			ID:             "ART-H002",
			Category:       string(CategoryFrameworkMappings),
			Severity:       SeverityHigh,
			Title:          "MITRE ATT&CK techniques incorrectly mapped",
			Description:    "One or more ATT&CK technique mappings do not match the actual attack behavior described.",
			Recommendation: "Review each technique against official ATT&CK definitions. Ensure technique matches observable behavior.",
			Effort:         "medium",
		},
		{
			ID:             "ART-H003",
			Category:       string(CategoryCompleteness),
			Severity:       SeverityHigh,
			Title:          "Missing required section: Mitigations",
			Description:    "Article does not include mitigation guidance for the vulnerability.",
			Recommendation: "Add Mitigations section with immediate, short-term, and long-term actions.",
			Effort:         "medium",
		},
		{
			ID:             "ART-H004",
			Category:       string(CategoryCompleteness),
			Severity:       SeverityHigh,
			Title:          "Missing required section: Affected Systems",
			Description:    "Article does not clearly identify which systems/versions are affected.",
			Recommendation: "Add Affected Systems section with version table and configuration details.",
			Effort:         "low",
		},
		{
			ID:             "ART-H005",
			Category:       string(CategoryActionability),
			Severity:       SeverityHigh,
			Title:          "No actionable detection guidance",
			Description:    "Article lacks concrete detection methods (IOCs, rules, queries) for identifying exploitation.",
			Recommendation: "Add Detection section with IOCs and at least one Sigma rule or SIEM query.",
			Effort:         "medium",
		},

		// Medium - Should Fix
		{
			ID:             "ART-M001",
			Category:       string(CategoryFrameworkMappings),
			Severity:       SeverityMedium,
			Title:          "Missing relevant CWE mapping",
			Description:    "Article does not map to the root cause CWE(s) for the vulnerability.",
			Recommendation: "Identify and add CWE mappings that describe the underlying weakness.",
			Effort:         "low",
		},
		{
			ID:             "ART-M002",
			Category:       string(CategoryDetectionContent),
			Severity:       SeverityMedium,
			Title:          "Detection rules not tested",
			Description:    "Sigma rules or SIEM queries are provided but may have syntax errors or logic issues.",
			Recommendation: "Validate detection rules against sample data or in test SIEM environment.",
			Effort:         "medium",
		},
		{
			ID:             "ART-M003",
			Category:       string(CategoryDiagramQuality),
			Severity:       SeverityMedium,
			Title:          "Diagrams use non-standard notation",
			Description:    "Architecture or attack diagrams don't follow standard DFD or sequence diagram conventions.",
			Recommendation: "Update diagrams to use standard notation (DFD shapes, UML sequence conventions).",
			Effort:         "medium",
		},
		{
			ID:             "ART-M004",
			Category:       string(CategorySourceAttribution),
			Severity:       SeverityMedium,
			Title:          "Original researchers not credited",
			Description:    "The security researchers who discovered the vulnerability are not properly credited.",
			Recommendation: "Add Credits section acknowledging original researchers by name/handle and organization.",
			Effort:         "low",
		},
		{
			ID:             "ART-M005",
			Category:       string(CategoryWritingQuality),
			Severity:       SeverityMedium,
			Title:          "Sensationalist or fear-mongering language",
			Description:    "Article uses unnecessarily alarming language that doesn't match the actual risk.",
			Recommendation: "Revise to use measured, professional tone. Let the facts convey severity.",
			Effort:         "low",
		},
		{
			ID:             "ART-M006",
			Category:       string(CategoryActionability),
			Severity:       SeverityMedium,
			Title:          "Mitigations lack timeframes",
			Description:    "Mitigation actions are listed but without priority or timing guidance.",
			Recommendation: "Categorize mitigations as Immediate (<24h), Short-term (<1 week), Long-term.",
			Effort:         "low",
		},

		// Low - Nice to Fix
		{
			ID:             "ART-L001",
			Category:       string(CategoryCompleteness),
			Severity:       SeverityLow,
			Title:          "Missing EPSS score context",
			Description:    "EPSS score is provided without explanation of what it means for prioritization.",
			Recommendation: "Add interpretation of EPSS percentile and comparison to typical CVE ranges.",
			Effort:         "low",
		},
		{
			ID:             "ART-L002",
			Category:       string(CategoryDiagramQuality),
			Severity:       SeverityLow,
			Title:          "Diagrams could benefit from color coding",
			Description:    "Diagrams are functional but don't use color to distinguish attack flows from normal flows.",
			Recommendation: "Add color coding for attack vs. legitimate flows. Ensure colorblind accessibility.",
			Effort:         "low",
		},
		{
			ID:             "ART-L003",
			Category:       string(CategoryDetectionContent),
			Severity:       SeverityLow,
			Title:          "Detection rules only cover one SIEM platform",
			Description:    "Detection content only includes queries for one platform (e.g., Splunk only).",
			Recommendation: "Consider adding queries for additional platforms (Elastic, Microsoft Sentinel).",
			Effort:         "medium",
		},
		{
			ID:             "ART-L004",
			Category:       string(CategoryWritingQuality),
			Severity:       SeverityLow,
			Title:          "Minor grammatical or stylistic issues",
			Description:    "Article has minor grammatical errors or stylistic inconsistencies.",
			Recommendation: "Proofread and correct grammatical issues. Ensure consistent style.",
			Effort:         "low",
		},

		// Info - Informational
		{
			ID:             "ART-I001",
			Category:       string(CategoryCompleteness),
			Severity:       SeverityInfo,
			Title:          "Enterprise considerations section could be expanded",
			Description:    "Enterprise section is present but could include more organizational guidance.",
			Recommendation: "Consider adding compliance implications, third-party risk notes, or change management guidance.",
			Effort:         "medium",
		},
		{
			ID:             "ART-I002",
			Category:       string(CategoryFrameworkMappings),
			Severity:       SeverityInfo,
			Title:          "Additional framework mappings available",
			Description:    "Article could include additional relevant framework mappings (e.g., ATLAS for AI, ASI for agents).",
			Recommendation: "Review if MITRE ATLAS, OWASP ASI, or other specialized frameworks are relevant.",
			Effort:         "low",
		},
	}
}

// ThreatModelFindingsCatalog returns common findings for threat model JSON files.
func ThreatModelFindingsCatalog() []FindingTemplate {
	return []FindingTemplate{
		// Critical
		{
			ID:             "TM-C001",
			Category:       string(CategorySchemaCompliance),
			Severity:       SeverityCritical,
			Title:          "Schema validation failure",
			Description:    "The threat model JSON does not pass schema validation.",
			Recommendation: "Run schema validator and fix all reported errors.",
			Effort:         "medium",
		},
		{
			ID:             "TM-C002",
			Category:       string(CategoryMappingAccuracy),
			Severity:       SeverityCritical,
			Title:          "CVE ID is invalid or does not exist",
			Description:    "The CVE ID referenced does not exist in NVD or is malformed.",
			Recommendation: "Verify CVE ID against NVD. Use correct format: CVE-YYYY-NNNNN.",
			Effort:         "low",
		},

		// High
		{
			ID:             "TM-H001",
			Category:       string(CategoryAttackModeling),
			Severity:       SeverityHigh,
			Title:          "Attack chain missing MITRE technique mappings",
			Description:    "Attack steps do not include MITRE ATT&CK technique references.",
			Recommendation: "Add mitreTactic and mitreTechnique to each attack step.",
			Effort:         "medium",
		},
		{
			ID:             "TM-H002",
			Category:       string(CategoryAssetIdentification),
			Severity:       SeverityHigh,
			Title:          "No assets defined",
			Description:    "The threat model does not identify any assets at risk.",
			Recommendation: "Add assets array with classification and ownership.",
			Effort:         "medium",
		},
		{
			ID:             "TM-H003",
			Category:       string(CategoryDiagramIntegration),
			Severity:       SeverityHigh,
			Title:          "Diagram element IDs don't match threat model",
			Description:    "Element IDs in diagrams don't correspond to elements defined in the threat model.",
			Recommendation: "Ensure consistent ID usage between diagrams and main threat model.",
			Effort:         "medium",
		},

		// Medium
		{
			ID:             "TM-M001",
			Category:       string(CategoryMitigationQuality),
			Severity:       SeverityMedium,
			Title:          "Mitigations lack status tracking",
			Description:    "Mitigations are defined but don't indicate implementation status.",
			Recommendation: "Add status field (implemented, planned, rejected) to each mitigation.",
			Effort:         "low",
		},
		{
			ID:             "TM-M002",
			Category:       string(CategoryThreatCoverage),
			Severity:       SeverityMedium,
			Title:          "Risk scores not justified",
			Description:    "Scenarios have risk scores but no rationale explaining the scoring.",
			Recommendation: "Add likelihoodRationale and impactRationale to scenario risk objects.",
			Effort:         "low",
		},
		{
			ID:             "TM-M003",
			Category:       string(CategoryCredentialFlows),
			Severity:       SeverityMedium,
			Title:          "Credential flow stages incomplete",
			Description:    "Credential flow is defined but missing key stages (e.g., exfiltration, reuse).",
			Recommendation: "Document complete credential lifecycle including all relevant stages.",
			Effort:         "medium",
		},

		// Low
		{
			ID:             "TM-L001",
			Category:       string(CategoryRedBlueContent),
			Severity:       SeverityLow,
			Title:          "Red team section could include more tools",
			Description:    "Red team section has exploitation steps but limited tool recommendations.",
			Recommendation: "Add tools array with name, purpose, and URL for each relevant tool.",
			Effort:         "low",
		},
		{
			ID:             "TM-L002",
			Category:       string(CategoryRedBlueContent),
			Severity:       SeverityLow,
			Title:          "Blue team hunting queries missing",
			Description:    "Blue team section has detection rules but no proactive hunting queries.",
			Recommendation: "Add huntingQueries array with platform-specific queries and hypotheses.",
			Effort:         "medium",
		},
	}
}

// DiagramFindingsCatalog returns common findings for security diagrams.
func DiagramFindingsCatalog() []FindingTemplate {
	return []FindingTemplate{
		// High
		{
			ID:             "DIA-H001",
			Category:       string(CategoryTrustBoundaries),
			Severity:       SeverityHigh,
			Title:          "Trust boundaries not marked",
			Description:    "Security diagram does not indicate trust boundaries between components.",
			Recommendation: "Add dashed lines or containers to mark trust boundaries. Label each boundary.",
			Effort:         "medium",
		},
		{
			ID:             "DIA-H002",
			Category:       string(CategoryAttackFlowClarity),
			Severity:       SeverityHigh,
			Title:          "Attack steps not numbered",
			Description:    "Attack flow diagram does not number the steps, making sequence unclear.",
			Recommendation: "Number each attack step in chronological order.",
			Effort:         "low",
		},
		{
			ID:             "DIA-H003",
			Category:       string(CategoryConsistency),
			Severity:       SeverityHigh,
			Title:          "Diagram contradicts article narrative",
			Description:    "The diagram shows a different attack flow than described in the article text.",
			Recommendation: "Align diagram with article. Update either diagram or text to match.",
			Effort:         "medium",
		},

		// Medium
		{
			ID:             "DIA-M001",
			Category:       string(CategoryNotationStandards),
			Severity:       SeverityMedium,
			Title:          "Inconsistent shape usage",
			Description:    "Different shapes are used for the same element type (e.g., processes).",
			Recommendation: "Use consistent DFD notation: circles=processes, rectangles=external entities.",
			Effort:         "low",
		},
		{
			ID:             "DIA-M002",
			Category:       string(CategoryDataFlowAccuracy),
			Severity:       SeverityMedium,
			Title:          "Data flows missing protocol labels",
			Description:    "Data flow arrows don't indicate the protocol used (HTTP, WebSocket, etc.).",
			Recommendation: "Label each flow with protocol and data type where relevant.",
			Effort:         "low",
		},
		{
			ID:             "DIA-M003",
			Category:       string(CategoryRenderingQuality),
			Severity:       SeverityMedium,
			Title:          "Diagram has overlapping elements",
			Description:    "Elements or labels overlap, reducing readability.",
			Recommendation: "Adjust layout to prevent overlapping. Consider splitting complex diagrams.",
			Effort:         "medium",
		},

		// Low
		{
			ID:             "DIA-L001",
			Category:       string(CategoryAccessibility),
			Severity:       SeverityLow,
			Title:          "Color is sole differentiator",
			Description:    "Diagram relies only on color to distinguish attack vs. normal flows.",
			Recommendation: "Add patterns, labels, or line styles as secondary differentiators.",
			Effort:         "low",
		},
		{
			ID:             "DIA-L002",
			Category:       string(CategoryAttackFlowClarity),
			Severity:       SeverityLow,
			Title:          "Missing MITRE technique annotations",
			Description:    "Attack steps could include MITRE ATT&CK technique IDs for reference.",
			Recommendation: "Add technique IDs (e.g., T1189) to relevant attack steps.",
			Effort:         "low",
		},
	}
}
