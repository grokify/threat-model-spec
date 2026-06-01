package evaluation

import (
	"fmt"
	"time"

	"github.com/plexusone/structured-evaluation/claims"
	"github.com/plexusone/structured-evaluation/evaluation"
)

// ToEvaluationReport converts an EvaluationResult to a structured-evaluation EvaluationReport.
// This enables integration with the broader structured-evaluation ecosystem.
func (er *EvaluationResult) ToEvaluationReport(document string) *evaluation.EvaluationReport {
	report := evaluation.NewEvaluationReport(er.RubricID, document)
	report.RubricVersion = er.RubricVersion

	// Convert categories
	for _, cat := range er.Categories {
		result := evaluation.CategoryResult{
			Category:  cat.Category,
			Score:     mapScoreValue(cat.Score),
			Reasoning: cat.Reasoning,
		}
		report.AddCategoryResult(result)
	}

	// Convert findings
	for _, f := range er.Findings {
		finding := evaluation.Finding{
			Severity:       mapSeverity(f.Severity),
			Category:       f.Category,
			Title:          f.Title,
			Description:    f.Description,
			Recommendation: f.Recommendation,
		}
		report.AddFinding(finding)
	}

	// Finalize without rubric (we don't have the full rubric object)
	report.Finalize(nil, "threat-model-spec/evaluation")
	return report
}

// ToClaimsReport extracts factual claims from an EvaluationResult for source validation.
// This is useful for verifying CVE details, CVSS scores, and other factual assertions.
func (er *EvaluationResult) ToClaimsReport(document string) *claims.ClaimsReport {
	report := claims.NewClaimsReport(document)
	report.Metadata.DocumentTitle = fmt.Sprintf("Evaluation: %s", er.RubricID)
	report.Metadata.GeneratedBy = "threat-model-spec/evaluation"

	claimIndex := 1

	// Extract claims from category evidence
	for _, cat := range er.Categories {
		for _, evidence := range cat.Evidence {
			claim := claims.NewClaim(
				fmt.Sprintf("cat-%s-%d", cat.Category, claimIndex),
				evidence,
				categorizeEvidence(cat.Category),
				claims.Location{Section: cat.Category},
			)

			// Mark as internal validation via LLM evaluation
			validation := claims.NewInternalValidation(
				claims.MethodObservation,
				"",    // No specific evidence path
				false, // LLM evaluations are not fully reproducible
			)
			validation.Internal.ValidatedBy = "LLM-as-Judge"
			validation.Internal.ValidatedAt = time.Now().UTC()
			claim.SetValidation(validation)

			// Set verdict based on category score
			claim.Verdict = mapScoreToVerdict(cat.Score)
			claim.Rationale = cat.Reasoning

			report.AddClaim(*claim)
			claimIndex++
		}
	}

	// Extract claims from findings
	for i, f := range er.Findings {
		claim := claims.NewClaim(
			fmt.Sprintf("finding-%d", i+1),
			f.Title,
			claims.ClaimTechnicalFinding,
			claims.Location{Section: f.Category},
		)

		validation := claims.NewInternalValidation(
			claims.MethodObservation,
			"",
			false,
		)
		validation.Internal.ValidatedBy = "LLM-as-Judge"
		claim.SetValidation(validation)

		// Findings are issues, so they need review
		claim.Verdict = claims.VerdictNeedsReview
		claim.Rationale = f.Description

		report.AddClaim(*claim)
	}

	report.Finalize()
	return report
}

// mapScoreValue converts local score strings to structured-evaluation ScoreValue.
func mapScoreValue(score string) evaluation.ScoreValue {
	switch score {
	case "pass":
		return evaluation.ScorePass
	case "partial":
		return evaluation.ScorePartial
	case "fail":
		return evaluation.ScoreFail
	default:
		return evaluation.ScoreFail
	}
}

// mapSeverity converts local Severity to structured-evaluation Severity.
func mapSeverity(s Severity) evaluation.Severity {
	switch s {
	case SeverityCritical:
		return evaluation.SeverityCritical
	case SeverityHigh:
		return evaluation.SeverityHigh
	case SeverityMedium:
		return evaluation.SeverityMedium
	case SeverityLow:
		return evaluation.SeverityLow
	case SeverityInfo:
		return evaluation.SeverityInfo
	default:
		return evaluation.SeverityInfo
	}
}

// mapScoreToVerdict converts score to claims verdict.
func mapScoreToVerdict(score string) claims.Verdict {
	switch score {
	case "pass":
		return claims.VerdictVerified
	case "partial":
		return claims.VerdictNeedsReview
	case "fail":
		return claims.VerdictRejected
	default:
		return claims.VerdictUnverified
	}
}

// categorizeEvidence maps category IDs to claim categories.
func categorizeEvidence(categoryID string) claims.ClaimCategory {
	switch categoryID {
	case CategoryTechnicalAccuracy:
		return claims.ClaimTechnicalFinding
	case CategorySourceAttribution:
		return claims.ClaimMetadata
	case CategoryFrameworkMappings:
		return claims.ClaimMetadata
	default:
		return claims.ClaimTechnicalFinding
	}
}

// FindingTemplateToFinding converts a FindingTemplate to a structured-evaluation Finding.
func FindingTemplateToFinding(ft FindingTemplate) evaluation.Finding {
	return evaluation.Finding{
		Severity:       mapSeverity(ft.Severity),
		Category:       ft.Category,
		Title:          ft.Title,
		Description:    ft.Description,
		Recommendation: ft.Recommendation,
	}
}
