package evaluation

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed rubrics/*.json
var embeddedRubrics embed.FS

// LoadRubricFromFile loads a rubric set from a JSON file.
func LoadRubricFromFile(path string) (*RubricSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rubric file: %w", err)
	}

	var rubric RubricSet
	if err := json.Unmarshal(data, &rubric); err != nil {
		return nil, fmt.Errorf("parsing rubric JSON: %w", err)
	}

	return &rubric, nil
}

// LoadEmbeddedRubric loads a rubric from the embedded rubrics directory.
// Name should be the filename without path (e.g., "vulnerability-article.rubric.json").
func LoadEmbeddedRubric(name string) (*RubricSet, error) {
	data, err := embeddedRubrics.ReadFile(filepath.Join("rubrics", name))
	if err != nil {
		return nil, fmt.Errorf("reading embedded rubric %s: %w", name, err)
	}

	var rubric RubricSet
	if err := json.Unmarshal(data, &rubric); err != nil {
		return nil, fmt.Errorf("parsing rubric JSON: %w", err)
	}

	return &rubric, nil
}

// ListEmbeddedRubrics returns the names of all embedded rubrics.
func ListEmbeddedRubrics() ([]string, error) {
	entries, err := embeddedRubrics.ReadDir("rubrics")
	if err != nil {
		return nil, fmt.Errorf("reading rubrics directory: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// VulnerabilityArticleRubric loads the embedded vulnerability article rubric.
func VulnerabilityArticleRubric() (*RubricSet, error) {
	return LoadEmbeddedRubric("vulnerability-article.rubric.json")
}

// ThreatModelRubric loads the embedded threat model rubric.
func ThreatModelRubric() (*RubricSet, error) {
	return LoadEmbeddedRubric("threat-model.rubric.json")
}

// DiagramRubric loads the embedded diagram rubric.
func DiagramRubric() (*RubricSet, error) {
	return LoadEmbeddedRubric("diagram.rubric.json")
}

// ToJSON serializes a rubric set to JSON.
func (rs *RubricSet) ToJSON() ([]byte, error) {
	return json.MarshalIndent(rs, "", "  ")
}

// ToPrompt generates an LLM-ready prompt from the rubric.
// If content is provided, it's inserted into the template.
func (rs *RubricSet) ToPrompt(content string) string {
	if rs.JudgePromptTemplate == "" {
		return rs.defaultPrompt(content)
	}

	// Simple placeholder replacement
	prompt := rs.JudgePromptTemplate
	// In a full implementation, use text/template
	return prompt
}

func (rs *RubricSet) defaultPrompt(content string) string {
	categoriesJSON, _ := json.MarshalIndent(rs.Categories, "", "  ")

	return fmt.Sprintf(`You are evaluating a document using the "%s" rubric.

## Document to Evaluate
%s

## Evaluation Categories
%s

## Instructions
For each category:
1. Analyze the document against the criteria
2. Provide reasoning (2-3 sentences)
3. List evidence (specific quotes or observations)
4. Assign a score based on the scale options
5. Note any findings (issues to fix)

Respond in JSON format matching the EvaluationResult schema.`,
		rs.Name,
		content,
		string(categoriesJSON),
	)
}

// Validate checks the rubric for common issues.
func (rs *RubricSet) Validate() []string {
	var issues []string

	if rs.ID == "" {
		issues = append(issues, "rubric ID is required")
	}
	if rs.Name == "" {
		issues = append(issues, "rubric name is required")
	}
	if rs.Version == "" {
		issues = append(issues, "rubric version is required")
	}
	if len(rs.Categories) == 0 {
		issues = append(issues, "at least one category is required")
	}

	for i, cat := range rs.Categories {
		if cat.ID == "" {
			issues = append(issues, fmt.Sprintf("category %d: ID is required", i))
		}
		if cat.Name == "" {
			issues = append(issues, fmt.Sprintf("category %s: name is required", cat.ID))
		}
		if len(cat.Scale.Options) == 0 && cat.Scale.Type == ScaleTypeCategorical {
			issues = append(issues, fmt.Sprintf("category %s: categorical scale requires options", cat.ID))
		}
	}

	return issues
}
