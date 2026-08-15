package evaluation

import (
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

// stageCalibrationFixture is a seeded-defect EvaluationResult: what a
// correctly functioning judge should output when grading a report that
// contains one specific, known defect for its stage. Each fixture scores
// at least one required category as non-"pass" — the calibration test
// below guards against rubber-stamp rubrics by proving each rubric+fixture
// pair can actually express a failing case, not just passing ones.
var stageCalibrationFixtures = map[ir.Stage]EvaluationResult{
	ir.StageProductDefinition: {
		RubricID:      "product-definition-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "asset_coverage", Score: "pass", Reasoning: "All assets identified with classification."},
			{Category: "invariant_completeness", Score: "fail", Reasoning: "The only stated invariant is 'the system should be secure' — not traceable to any source spec and not falsifiable."},
			{Category: "threat_actor_realism", Score: "partial", Reasoning: "Generic external-attacker profile only."},
			{Category: "abuse_case_grounding", Score: "pass", Reasoning: "Scenarios have concrete preconditions and business impact."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: invariants are generic boilerplate with no traceability to the source PRD.",
	},
	ir.StageBuilderDefinition: {
		RubricID:      "builder-definition-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "boundary_coverage", Score: "pass", Reasoning: "Every external-facing flow crosses a declared boundary."},
			{Category: "threat_completeness", Score: "fail", Reasoning: "The webhook-handler flow crosses the localhost trust boundary but has zero STRIDE-mapped findings."},
			{Category: "control_mapping", Score: "pass", Reasoning: "Every validated threat has a specific mitigation."},
			{Category: "api_contract_drift", Score: "partial", Reasoning: "No Product Definition draft existed to compare against."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: a boundary-crossing flow has no threat analysis at all.",
	},
	ir.StageImplementation: {
		RubricID:      "implementation-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "evidence_support", Score: "pass", Reasoning: "Every finding cites a file+line evidence locator."},
			{Category: "reachability", Score: "fail", Reasoning: "The SQL-injection finding cites a risky string-concatenation pattern but never establishes that request input reaches it — the value may originate from a trusted internal config."},
			{Category: "aspm_domain_coverage", Score: "pass", Reasoning: "All 5 implementation ASPM domains analyzed."},
			{Category: "drift_detection", Score: "partial", Reasoning: "No ArchitectureAssertion recorded despite design intent being available."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: a plausible-looking vulnerability finding lacks reachability analysis.",
	},
	ir.StageDeployment: {
		RubricID:      "deployment-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "evidence_support", Score: "pass", Reasoning: "Every finding cites a config locator."},
			{Category: "deployed_control_verification", Score: "fail", Reasoning: "The report states the admin API 'should be private per the design' but never checks the actual ingress rule — which in fact exposes it publicly."},
			{Category: "aspm_domain_coverage", Score: "pass", Reasoning: "All 4 deployment ASPM domains analyzed."},
			{Category: "exposure_drift", Score: "fail", Reasoning: "No ArchitectureAssertion comparing deployed exposure to design intent, despite the design requiring private exposure."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: a required control (private admin API) is assumed present rather than verified against the deployed ingress config.",
	},
	ir.StageBuilderOperations: {
		RubricID:      "builder-operations-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "detection_coverage", Score: "pass", Reasoning: "Detection coverage assessed against the product's actual threat model."},
			{Category: "incident_evidence_grounding", Score: "pass", Reasoning: "Incident findings cite the incident artifact."},
			{Category: "dynamic_testing_disclosure", Score: "fail", Reasoning: "The report contains no findings and no statement about whether dynamic testing was performed — a reader cannot tell whether this means 'tested and clean' or 'never tested'."},
			{Category: "control_effectiveness", Score: "partial", Reasoning: "Controls listed but effectiveness not assessed."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: dynamic-testing scope is undisclosed, so an absence of findings is ambiguous.",
	},
	ir.StageProductOperations: {
		RubricID:      "product-operations-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{Category: "invariant_drift_detection", Score: "fail", Reasoning: "The critical tenant-isolation invariant from Product Definition has no corresponding ArchitectureAssertion checked against production telemetry."},
			{Category: "adoption_signal_completeness", Score: "pass", Reasoning: "Report includes activation and retention signal."},
			{Category: "evidence_grounding", Score: "pass", Reasoning: "Findings cite specific telemetry queries."},
		},
		OverallDecision: "fail",
		Summary:         "Seeded defect: a critical invariant is never checked against production reality.",
	},
}

// TestStageRubrics_AreStructurallyValid guards against a rubric that
// doesn't even parse into a usable RubricSet (missing IDs, empty
// categorical scales, etc.) using the package's own Validate().
func TestStageRubrics_AreStructurallyValid(t *testing.T) {
	for _, stage := range ir.AllStages() {
		rubric, err := StageRubric(stage)
		if err != nil {
			t.Fatalf("StageRubric(%q) error: %v", stage, err)
		}
		if issues := rubric.Validate(); len(issues) > 0 {
			t.Errorf("StageRubric(%q) has validation issues: %v", stage, issues)
		}
	}
}

// TestStageRubrics_CalibrationFixturesExistForEveryStage ensures the
// fixture map itself hasn't drifted from the six canonical stages.
func TestStageRubrics_CalibrationFixturesExistForEveryStage(t *testing.T) {
	if len(stageCalibrationFixtures) != 6 {
		t.Fatalf("len(stageCalibrationFixtures) = %d, want 6", len(stageCalibrationFixtures))
	}
	for _, stage := range ir.AllStages() {
		if _, ok := stageCalibrationFixtures[stage]; !ok {
			t.Errorf("no calibration fixture for stage %q", stage)
		}
	}
}

// TestStageRubrics_FixtureCategoriesMatchRubric catches drift between a
// rubric's category IDs and its fixture's category IDs — a rubric that
// renamed a category without updating its fixture would silently stop
// being calibration-tested.
func TestStageRubrics_FixtureCategoriesMatchRubric(t *testing.T) {
	for _, stage := range ir.AllStages() {
		rubric, err := StageRubric(stage)
		if err != nil {
			t.Fatalf("StageRubric(%q) error: %v", stage, err)
		}
		rubricCategoryIDs := make(map[string]bool, len(rubric.Categories))
		for _, c := range rubric.Categories {
			rubricCategoryIDs[c.ID] = true
		}

		fixture := stageCalibrationFixtures[stage]
		for _, cr := range fixture.Categories {
			if !rubricCategoryIDs[cr.Category] {
				t.Errorf("stage %q: fixture scores unknown category %q", stage, cr.Category)
			}
		}
	}
}

// TestStageRubrics_CalibrationFixturesProduceNonPassingRequiredCategory is
// the core calibration guard (RMI-THREATMODELSPEC-108): each stage's
// seeded-defect fixture must score at least one *required* category as
// non-"pass". A rubric where every fixture trivially passes everything
// would be a rubber stamp; this test proves each rubric can actually fail
// a report on the specific defect its fixture represents.
func TestStageRubrics_CalibrationFixturesProduceNonPassingRequiredCategory(t *testing.T) {
	for _, stage := range ir.AllStages() {
		rubric, err := StageRubric(stage)
		if err != nil {
			t.Fatalf("StageRubric(%q) error: %v", stage, err)
		}
		requiredCategoryIDs := make(map[string]bool)
		for _, c := range rubric.Categories {
			if c.Required {
				requiredCategoryIDs[c.ID] = true
			}
		}
		if len(requiredCategoryIDs) == 0 {
			t.Fatalf("stage %q rubric has no required categories at all", stage)
		}

		fixture := stageCalibrationFixtures[stage]
		var sawNonPassingRequired bool
		for _, cr := range fixture.Categories {
			if requiredCategoryIDs[cr.Category] && cr.Score != "pass" {
				sawNonPassingRequired = true
				break
			}
		}
		if !sawNonPassingRequired {
			t.Errorf("stage %q: calibration fixture does not score any required category as non-passing — rubric may be a rubber stamp", stage)
		}
	}
}
