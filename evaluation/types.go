// Package evaluation provides types and utilities for evaluating vulnerability
// documentation using LLM-as-Judge workflows.
//
// The schema follows Go-first principles: Go types are the source of truth,
// JSON Schema is generated from them. Rubric implementations are JSON data
// files that conform to the schema.
package evaluation

// RubricSet is a collection of rubrics for evaluating a document type.
type RubricSet struct {
	// ID uniquely identifies this rubric set.
	ID string `json:"id"`

	// Name is the human-readable name.
	Name string `json:"name"`

	// Version is the semantic version of this rubric.
	Version string `json:"version"`

	// Description explains what this rubric set evaluates.
	Description string `json:"description,omitempty"`

	// EvaluationType is "analytic" (per-category) or "holistic" (single score).
	// Analytic is recommended for LLM-as-Judge.
	EvaluationType EvaluationType `json:"evaluationType,omitempty"`

	// PassCriteria defines requirements for overall pass/fail.
	PassCriteria PassCriteria `json:"passCriteria"`

	// Categories are the evaluation dimensions.
	Categories []Category `json:"categories"`

	// JudgePromptTemplate is the prompt template for LLM evaluation.
	// Supports placeholders: {article_content}, {categories}, etc.
	JudgePromptTemplate string `json:"judgePromptTemplate,omitempty"`

	// Metadata contains additional information about the rubric.
	Metadata *RubricMetadata `json:"metadata,omitempty"`
}

// EvaluationType defines how evaluation is performed.
type EvaluationType string

const (
	// EvaluationTypeAnalytic scores each category independently (recommended).
	EvaluationTypeAnalytic EvaluationType = "analytic"

	// EvaluationTypeHolistic provides a single overall score.
	EvaluationTypeHolistic EvaluationType = "holistic"
)

// Category is a single evaluation dimension.
type Category struct {
	// ID uniquely identifies this category within the rubric.
	ID string `json:"id"`

	// Name is the human-readable category name.
	Name string `json:"name"`

	// Description explains what this category measures.
	Description string `json:"description"`

	// Weight is the relative importance (default 1.0).
	Weight float64 `json:"weight,omitempty"`

	// Required indicates if this category must pass for overall pass.
	Required bool `json:"required,omitempty"`

	// Scale defines how this category is scored.
	Scale Scale `json:"scale"`

	// EvaluationPrompt is a specific prompt for evaluating this category.
	EvaluationPrompt string `json:"evaluationPrompt,omitempty"`

	// Examples provides few-shot examples for LLM evaluation.
	Examples *CategoryExamples `json:"examples,omitempty"`
}

// Scale defines the scoring mechanism for a category.
type Scale struct {
	// Type is "categorical", "checklist", or "binary".
	// Categorical with 2-3 options is recommended for LLM-as-Judge.
	Type ScaleType `json:"type"`

	// Options are the scoring options (for categorical scales).
	Options []ScaleOption `json:"options,omitempty"`

	// RequiredItems are items that must be present (for checklist scales).
	RequiredItems []string `json:"requiredItems,omitempty"`

	// OptionalItems are items that add value (for checklist scales).
	OptionalItems []string `json:"optionalItems,omitempty"`

	// PassingThreshold defines pass criteria (for checklist scales).
	PassingThreshold *ChecklistThreshold `json:"passingThreshold,omitempty"`
}

// ScaleType defines the type of scoring scale.
type ScaleType string

const (
	// ScaleTypeCategorical uses discrete categories (pass/partial/fail).
	// Recommended for LLM-as-Judge - better calibrated than numeric.
	ScaleTypeCategorical ScaleType = "categorical"

	// ScaleTypeChecklist uses a list of required/optional items.
	ScaleTypeChecklist ScaleType = "checklist"

	// ScaleTypeBinary is simple pass/fail.
	ScaleTypeBinary ScaleType = "binary"

	// ScaleTypeNumeric uses numeric scores (0-10).
	// Less recommended for LLM evaluation due to calibration issues.
	ScaleTypeNumeric ScaleType = "numeric"
)

// ScaleOption is a single option in a categorical scale.
type ScaleOption struct {
	// Value is the machine-readable value (e.g., "pass", "partial", "fail").
	Value string `json:"value"`

	// Label is the human-readable label.
	Label string `json:"label"`

	// Criteria are specific requirements for this score level.
	Criteria []string `json:"criteria"`
}

// ChecklistThreshold defines pass criteria for checklist scales.
type ChecklistThreshold struct {
	// Required is "all" or a number of required items that must be present.
	Required string `json:"required,omitempty"`

	// Optional is the minimum number of optional items needed.
	Optional int `json:"optional,omitempty"`
}

// CategoryExamples provides few-shot examples for a category.
// Research shows 1 example per level improves LLM alignment.
type CategoryExamples struct {
	Pass    *Example `json:"pass,omitempty"`
	Partial *Example `json:"partial,omitempty"`
	Fail    *Example `json:"fail,omitempty"`
}

// Example is a few-shot example for LLM evaluation.
type Example struct {
	// Excerpt is example content from an article.
	Excerpt string `json:"excerpt"`

	// Reasoning explains why this gets this score.
	// Including reasoning improves LLM alignment (chain-of-thought).
	Reasoning string `json:"reasoning"`
}

// PassCriteria defines requirements for overall pass/fail determination.
type PassCriteria struct {
	// MinCategoriesPassing is "all", "all_required", or a number.
	MinCategoriesPassing string `json:"minCategoriesPassing,omitempty"`

	// MaxFindings limits findings by severity.
	MaxFindings *FindingLimits `json:"maxFindingsSeverity,omitempty"`
}

// FindingLimits sets maximum allowed findings per severity.
// Use -1 for unlimited.
type FindingLimits struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low,omitempty"`
}

// RubricMetadata contains additional rubric information.
type RubricMetadata struct {
	CreatedAt string   `json:"createdAt,omitempty"`
	Author    string   `json:"author,omitempty"`
	BasedOn   []string `json:"basedOn,omitempty"`
}

// Finding represents an issue discovered during evaluation.
// Severity type is defined in findings_catalog.go.
type Finding struct {
	ID             string   `json:"id,omitempty"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

// EvaluationResult is the output from an LLM judge evaluation.
type EvaluationResult struct {
	// RubricID identifies the rubric used.
	RubricID string `json:"rubricId"`

	// RubricVersion is the version of the rubric used.
	RubricVersion string `json:"rubricVersion"`

	// Categories contains per-category results.
	Categories []CategoryResult `json:"categories"`

	// Findings are issues discovered during evaluation.
	Findings []Finding `json:"findings,omitempty"`

	// OverallDecision is pass/conditional/fail.
	OverallDecision string `json:"overallDecision"`

	// Summary is a brief explanation of the decision.
	Summary string `json:"summary"`
}

// CategoryResult is the evaluation result for a single category.
type CategoryResult struct {
	// Category is the category ID.
	Category string `json:"category"`

	// Score is the assigned score (e.g., "pass", "partial", "fail").
	Score string `json:"score"`

	// Reasoning explains the score (chain-of-thought).
	Reasoning string `json:"reasoning"`

	// Evidence are specific quotes or observations.
	Evidence []string `json:"evidence,omitempty"`
}
