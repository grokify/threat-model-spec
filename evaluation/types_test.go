package evaluation

import (
	"encoding/json"
	"testing"
)

func TestLoadEmbeddedRubrics(t *testing.T) {
	rubrics, err := ListEmbeddedRubrics()
	if err != nil {
		t.Fatalf("Failed to list embedded rubrics: %v", err)
	}

	if len(rubrics) == 0 {
		t.Error("Expected at least one embedded rubric")
	}

	expected := map[string]bool{
		"vulnerability-article.rubric.json": true,
		"threat-model.rubric.json":          true,
		"diagram.rubric.json":               true,
	}

	for _, name := range rubrics {
		if !expected[name] {
			t.Logf("Found rubric: %s", name)
		}
		delete(expected, name)
	}

	for name := range expected {
		t.Errorf("Missing expected rubric: %s", name)
	}
}

func TestVulnerabilityArticleRubric(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load vulnerability article rubric: %v", err)
	}

	if rubric.ID != "vulnerability-article-v1" {
		t.Errorf("Expected ID 'vulnerability-article-v1', got %s", rubric.ID)
	}

	if len(rubric.Categories) == 0 {
		t.Error("Expected at least one category")
	}

	// Check required categories exist
	requiredCategories := []string{
		"technical_accuracy",
		"responsible_disclosure",
		"completeness",
		"actionability",
	}

	categoryMap := make(map[string]Category)
	for _, cat := range rubric.Categories {
		categoryMap[cat.ID] = cat
	}

	for _, reqCat := range requiredCategories {
		cat, exists := categoryMap[reqCat]
		if !exists {
			t.Errorf("Missing required category: %s", reqCat)
			continue
		}
		if !cat.Required {
			t.Errorf("Category %s should be marked as required", reqCat)
		}
	}
}

func TestThreatModelRubric(t *testing.T) {
	rubric, err := ThreatModelRubric()
	if err != nil {
		t.Fatalf("Failed to load threat model rubric: %v", err)
	}

	if rubric.ID != "threat-model-v1" {
		t.Errorf("Expected ID 'threat-model-v1', got %s", rubric.ID)
	}

	// Verify schema compliance is required and weighted high
	for _, cat := range rubric.Categories {
		if cat.ID == "schema_compliance" {
			if !cat.Required {
				t.Error("schema_compliance should be required")
			}
			if cat.Weight < 1.0 {
				t.Error("schema_compliance should have weight >= 1.0")
			}
		}
	}
}

func TestDiagramRubric(t *testing.T) {
	rubric, err := DiagramRubric()
	if err != nil {
		t.Fatalf("Failed to load diagram rubric: %v", err)
	}

	if rubric.ID != "diagram-v1" {
		t.Errorf("Expected ID 'diagram-v1', got %s", rubric.ID)
	}

	// Verify trust boundaries category exists and is required
	var hasTrustBoundaries bool
	for _, cat := range rubric.Categories {
		if cat.ID == "trust_boundaries" {
			hasTrustBoundaries = true
			if !cat.Required {
				t.Error("trust_boundaries should be required for security diagrams")
			}
		}
	}

	if !hasTrustBoundaries {
		t.Error("Missing trust_boundaries category")
	}
}

func TestRubricValidation(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load rubric: %v", err)
	}

	issues := rubric.Validate()
	if len(issues) > 0 {
		for _, issue := range issues {
			t.Errorf("Validation issue: %s", issue)
		}
	}
}

func TestRubricToJSON(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load rubric: %v", err)
	}

	jsonData, err := rubric.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize rubric: %v", err)
	}

	// Verify it's valid JSON
	var parsed RubricSet
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Generated JSON is invalid: %v", err)
	}

	if parsed.ID != rubric.ID {
		t.Error("Roundtrip failed: ID mismatch")
	}
}

func TestCategoricalScaleOptions(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load rubric: %v", err)
	}

	for _, cat := range rubric.Categories {
		if cat.Scale.Type != ScaleTypeCategorical {
			continue
		}

		// Verify 2-3 options (recommended for LLM)
		optCount := len(cat.Scale.Options)
		if optCount < 2 || optCount > 5 {
			t.Errorf("Category %s: expected 2-5 options, got %d", cat.ID, optCount)
		}

		// Verify each option has criteria
		for _, opt := range cat.Scale.Options {
			if len(opt.Criteria) == 0 {
				t.Errorf("Category %s, option %s: missing criteria", cat.ID, opt.Value)
			}
		}
	}
}

func TestPassCriteria(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load rubric: %v", err)
	}

	if rubric.PassCriteria.MaxFindings == nil {
		t.Error("PassCriteria.MaxFindings should be set")
		return
	}

	// Verify no critical/high allowed for publication
	if rubric.PassCriteria.MaxFindings.Critical != 0 {
		t.Error("Publication rubric should allow 0 critical findings")
	}
	if rubric.PassCriteria.MaxFindings.High != 0 {
		t.Error("Publication rubric should allow 0 high findings")
	}
}

func TestExamplesPresent(t *testing.T) {
	rubric, err := VulnerabilityArticleRubric()
	if err != nil {
		t.Fatalf("Failed to load rubric: %v", err)
	}

	// At least some categories should have examples (for LLM few-shot)
	exampleCount := 0
	for _, cat := range rubric.Categories {
		if cat.Examples != nil {
			exampleCount++
			if cat.Examples.Pass != nil && cat.Examples.Pass.Reasoning == "" {
				t.Errorf("Category %s: pass example missing reasoning", cat.ID)
			}
		}
	}

	// Expect at least 2 categories with examples
	if exampleCount < 2 {
		t.Logf("Warning: Only %d categories have examples (few-shot improves LLM alignment)", exampleCount)
	}
}
