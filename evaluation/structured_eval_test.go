package evaluation

import (
	"testing"

	"github.com/plexusone/structured-evaluation/claims"
	"github.com/plexusone/structured-evaluation/evaluation"
)

func TestEvaluationResult_ToEvaluationReport(t *testing.T) {
	result := &EvaluationResult{
		RubricID:      "vulnerability-article-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{
				Category:  "technical_accuracy",
				Score:     "pass",
				Reasoning: "CVE details match NVD exactly",
				Evidence:  []string{"CVE details verified with CVSS 8.8"},
			},
			{
				Category:  "responsible_disclosure",
				Score:     "partial",
				Reasoning: "Patch available but timeline unclear",
				Evidence:  []string{"Patch released 2026-01-29"},
			},
		},
		Findings: []Finding{
			{
				ID:             "F001",
				Category:       "technical_accuracy",
				Severity:       SeverityMedium,
				Title:          "Missing CWE mapping",
				Description:    "CWE-346 should be mentioned",
				Recommendation: "Add CWE-346 reference",
			},
		},
		OverallDecision: "conditional",
		Summary:         "Article needs minor improvements",
	}

	report := result.ToEvaluationReport("article.md")

	// Verify report metadata
	if report.ReviewType != "vulnerability-article-v1" {
		t.Errorf("expected ReviewType 'vulnerability-article-v1', got %q", report.ReviewType)
	}
	if report.RubricVersion != "1.0.0" {
		t.Errorf("expected RubricVersion '1.0.0', got %q", report.RubricVersion)
	}

	// Verify categories
	if len(report.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(report.Categories))
	}
	if report.Categories[0].Score != evaluation.ScorePass {
		t.Errorf("expected first category to be pass, got %v", report.Categories[0].Score)
	}
	if report.Categories[1].Score != evaluation.ScorePartial {
		t.Errorf("expected second category to be partial, got %v", report.Categories[1].Score)
	}

	// Verify findings
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Severity != evaluation.SeverityMedium {
		t.Errorf("expected severity medium, got %v", report.Findings[0].Severity)
	}
}

func TestEvaluationResult_ToClaimsReport(t *testing.T) {
	result := &EvaluationResult{
		RubricID:      "vulnerability-article-v1",
		RubricVersion: "1.0.0",
		Categories: []CategoryResult{
			{
				Category:  "technical_accuracy",
				Score:     "pass",
				Reasoning: "All technical details verified",
				Evidence: []string{
					"CVE CVSS 8.8 verified against NVD",
					"Attack chain is technically feasible",
				},
			},
		},
		Findings: []Finding{
			{
				Category:    "source_attribution",
				Severity:    SeverityLow,
				Title:       "Missing vendor advisory link",
				Description: "Should link to official vendor advisory",
			},
		},
		OverallDecision: "pass",
		Summary:         "Article meets quality standards",
	}

	report := result.ToClaimsReport("article.md")

	// Should have 2 evidence claims + 1 finding claim = 3 total
	if len(report.Claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(report.Claims))
	}

	// Check first evidence claim
	claim1 := report.Claims[0]
	if claim1.Verdict != claims.VerdictVerified {
		t.Errorf("expected verdict verified for pass category, got %v", claim1.Verdict)
	}
	if claim1.Category != claims.ClaimTechnicalFinding {
		t.Errorf("expected category ClaimTechnicalFinding, got %v", claim1.Category)
	}

	// Check finding claim
	findingClaim := report.Claims[2]
	if findingClaim.Verdict != claims.VerdictNeedsReview {
		t.Errorf("expected verdict needs-review for finding, got %v", findingClaim.Verdict)
	}
}

func TestMapScoreValue(t *testing.T) {
	tests := []struct {
		input    string
		expected evaluation.ScoreValue
	}{
		{"pass", evaluation.ScorePass},
		{"partial", evaluation.ScorePartial},
		{"fail", evaluation.ScoreFail},
		{"unknown", evaluation.ScoreFail},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapScoreValue(tt.input)
			if result != tt.expected {
				t.Errorf("mapScoreValue(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    Severity
		expected evaluation.Severity
	}{
		{SeverityCritical, evaluation.SeverityCritical},
		{SeverityHigh, evaluation.SeverityHigh},
		{SeverityMedium, evaluation.SeverityMedium},
		{SeverityLow, evaluation.SeverityLow},
		{SeverityInfo, evaluation.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := mapSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("mapSeverity(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFindingTemplateToFinding(t *testing.T) {
	template := FindingTemplate{
		ID:             "ART-C001",
		Category:       "technical_accuracy",
		Severity:       SeverityCritical,
		Title:          "CVE details do not match NVD",
		Description:    "The CVE ID contradicts the official record",
		Recommendation: "Verify against NVD",
		Effort:         "low",
	}

	finding := FindingTemplateToFinding(template)

	if finding.Severity != evaluation.SeverityCritical {
		t.Errorf("expected severity critical, got %v", finding.Severity)
	}
	if finding.Category != "technical_accuracy" {
		t.Errorf("expected category 'technical_accuracy', got %q", finding.Category)
	}
	if finding.Title != "CVE details do not match NVD" {
		t.Errorf("expected title 'CVE details do not match NVD', got %q", finding.Title)
	}
}
