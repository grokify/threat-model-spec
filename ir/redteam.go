package ir

import "github.com/invopop/jsonschema"

// ExploitDifficulty indicates how difficult it is to exploit a vulnerability.
type ExploitDifficulty string

const (
	ExploitDifficultyTrivial ExploitDifficulty = "trivial"
	ExploitDifficultyLow     ExploitDifficulty = "low"
	ExploitDifficultyMedium  ExploitDifficulty = "medium"
	ExploitDifficultyHigh    ExploitDifficulty = "high"
	ExploitDifficultyExpert  ExploitDifficulty = "expert"
)

// JSONSchema implements jsonschema.JSONSchemaer for ExploitDifficulty.
func (ExploitDifficulty) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"trivial", "low", "medium", "high", "expert"},
	}
}

// ExploitationGuidance provides red team/offensive security guidance
// for testing and validating vulnerabilities.
type ExploitationGuidance struct {
	// Prerequisites lists conditions that must be true for exploitation.
	// Example: "Target must have WebSocket gateway enabled on localhost:9999"
	Prerequisites []string `json:"prerequisites,omitempty"`

	// ExploitationSteps provides ordered steps for exploiting the vulnerability.
	ExploitationSteps []ExploitationStep `json:"exploitationSteps,omitempty"`

	// Tools lists offensive security tools useful for testing.
	Tools []OffensiveTool `json:"tools,omitempty"`

	// PayloadPatterns provides generic payload templates for testing.
	// Note: These are patterns, not actual exploits.
	PayloadPatterns []PayloadPattern `json:"payloadPatterns,omitempty"`

	// SuccessIndicators describes how to verify successful exploitation.
	SuccessIndicators []string `json:"successIndicators,omitempty"`

	// Difficulty indicates the overall exploitation difficulty.
	Difficulty ExploitDifficulty `json:"difficulty,omitempty"`

	// TestRefs links to app-test-spec test cases for automated validation.
	TestRefs []TestReference `json:"testRefs,omitempty"`

	// Notes provides additional guidance for penetration testers.
	Notes string `json:"notes,omitempty"`

	// TimeToExploit is an estimate of exploitation time (e.g., "< 1 minute").
	TimeToExploit string `json:"timeToExploit,omitempty"`

	// SkillLevel indicates the required attacker skill level.
	SkillLevel string `json:"skillLevel,omitempty"`
}

// ExploitationStep represents a single step in an exploitation process.
type ExploitationStep struct {
	// Step is the sequence number (1, 2, 3...).
	Step int `json:"step"`

	// Action describes what the attacker does.
	Action string `json:"action"`

	// Description provides detailed explanation of this step.
	Description string `json:"description,omitempty"`

	// Tool identifies the tool used for this step (if any).
	Tool string `json:"tool,omitempty"`

	// Example provides a concrete command or code example.
	// Note: Examples should be educational, not weaponized.
	Example string `json:"example,omitempty"`

	// ExpectedResult describes what should happen after this step.
	ExpectedResult string `json:"expectedResult,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID (e.g., T1110).
	MITRETechnique string `json:"mitreTechnique,omitempty"`
}

// OffensiveTool describes a security testing tool.
type OffensiveTool struct {
	// Name is the tool name (e.g., "Burp Suite", "sqlmap", "nuclei").
	Name string `json:"name"`

	// Purpose describes what the tool is used for.
	Purpose string `json:"purpose,omitempty"`

	// URL is a link to the tool's website or repository.
	URL string `json:"url,omitempty"`

	// Template provides a command template or configuration snippet.
	Template string `json:"template,omitempty"`

	// Category categorizes the tool (e.g., "scanner", "proxy", "fuzzer").
	Category string `json:"category,omitempty"`

	// License indicates the tool's license (e.g., "open-source", "commercial").
	License string `json:"license,omitempty"`
}

// PayloadPattern provides a generic pattern for security testing payloads.
// These are educational patterns, not weaponized exploits.
type PayloadPattern struct {
	// Type categorizes the payload (e.g., "sqli", "xss", "ssrf", "websocket").
	Type string `json:"type"`

	// Pattern is the payload pattern or template.
	// Use placeholders like {TARGET}, {INPUT}, {PAYLOAD} for customization.
	Pattern string `json:"pattern"`

	// Description explains what this payload tests for.
	Description string `json:"description,omitempty"`

	// Variants lists variations of this payload pattern.
	Variants []string `json:"variants,omitempty"`

	// Encoding specifies any encoding applied (e.g., "base64", "url", "none").
	Encoding string `json:"encoding,omitempty"`

	// BypassTarget describes what defense this payload attempts to bypass.
	BypassTarget string `json:"bypassTarget,omitempty"`
}
