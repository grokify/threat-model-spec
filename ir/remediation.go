package ir

// RemediationGuidance provides guidance for developers to fix vulnerabilities.
type RemediationGuidance struct {
	// VulnerablePatterns shows code patterns that are vulnerable.
	VulnerablePatterns []CodePattern `json:"vulnerablePatterns,omitempty"`

	// SecurePatterns shows secure code patterns that fix the vulnerability.
	SecurePatterns []CodePattern `json:"securePatterns,omitempty"`

	// ReviewChecklist provides items to check during code review.
	ReviewChecklist []ChecklistItem `json:"reviewChecklist,omitempty"`

	// RecommendedLibraries lists libraries that help mitigate the vulnerability.
	RecommendedLibraries []Library `json:"recommendedLibraries,omitempty"`

	// ConfigurationChanges lists configuration changes to fix the vulnerability.
	ConfigurationChanges []ConfigChange `json:"configurationChanges,omitempty"`

	// TestingApproach describes how to verify the fix is effective.
	TestingApproach *TestingApproach `json:"testingApproach,omitempty"`

	// TimeToFix estimates how long the fix will take (e.g., "2-4 hours").
	TimeToFix string `json:"timeToFix,omitempty"`

	// Complexity indicates fix complexity (trivial, low, medium, high).
	Complexity string `json:"complexity,omitempty"`

	// BreakingChanges notes any breaking changes introduced by the fix.
	BreakingChanges []string `json:"breakingChanges,omitempty"`

	// Notes provides additional guidance for developers.
	Notes string `json:"notes,omitempty"`
}

// CodePattern represents a code pattern (vulnerable or secure).
type CodePattern struct {
	// Language is the programming language (e.g., "go", "python", "javascript").
	Language string `json:"language"`

	// Description explains this code pattern.
	Description string `json:"description"`

	// Code is the actual code snippet.
	Code string `json:"code"`

	// Explanation provides detailed explanation of why this is vulnerable/secure.
	Explanation string `json:"explanation,omitempty"`

	// CWE is the CWE ID for the vulnerability type (for vulnerable patterns).
	CWE string `json:"cwe,omitempty"`

	// Framework specifies the framework (e.g., "net/http", "gin", "express").
	Framework string `json:"framework,omitempty"`

	// FilePath suggests where this pattern typically appears.
	FilePath string `json:"filePath,omitempty"`

	// LineRange indicates relevant line numbers (e.g., "45-60").
	LineRange string `json:"lineRange,omitempty"`
}

// ChecklistItem is a single item in a code review checklist.
type ChecklistItem struct {
	// Item is the checklist item description.
	Item string `json:"item"`

	// Required indicates if this item is required for the fix to be complete.
	Required bool `json:"required,omitempty"`

	// Notes provides additional context for reviewers.
	Notes string `json:"notes,omitempty"`

	// Category categorizes the item (e.g., "validation", "authentication", "logging").
	Category string `json:"category,omitempty"`

	// Severity indicates how critical this item is (critical, high, medium, low).
	Severity string `json:"severity,omitempty"`
}

// Library represents a recommended library for vulnerability mitigation.
type Library struct {
	// Name is the library name (e.g., "validator", "helmet", "sanitize-html").
	Name string `json:"name"`

	// Language is the programming language.
	Language string `json:"language"`

	// Purpose describes what the library helps with.
	Purpose string `json:"purpose"`

	// URL is a link to the library's website or repository.
	URL string `json:"url,omitempty"`

	// Examples shows example usage of the library.
	Examples []string `json:"examples,omitempty"`

	// Version is the recommended minimum version.
	Version string `json:"version,omitempty"`

	// InstallCommand shows how to install the library.
	InstallCommand string `json:"installCommand,omitempty"`

	// License is the library's license.
	License string `json:"license,omitempty"`

	// Alternatives lists alternative libraries.
	Alternatives []string `json:"alternatives,omitempty"`
}

// ConfigChange represents a configuration change to fix a vulnerability.
type ConfigChange struct {
	// Setting is the configuration setting name.
	Setting string `json:"setting"`

	// Value is the recommended value.
	Value string `json:"value"`

	// Description explains why this change is needed.
	Description string `json:"description,omitempty"`

	// Platform specifies the platform or application this applies to.
	Platform string `json:"platform,omitempty"`

	// File is the configuration file path.
	File string `json:"file,omitempty"`

	// CurrentValue shows the vulnerable/default value (for comparison).
	CurrentValue string `json:"currentValue,omitempty"`

	// Impact describes the impact of this change.
	Impact string `json:"impact,omitempty"`

	// RestartRequired indicates if a restart is needed.
	RestartRequired bool `json:"restartRequired,omitempty"`
}

// TestingApproach describes how to verify a fix is effective.
type TestingApproach struct {
	// UnitTests describes unit tests that should pass after the fix.
	UnitTests []string `json:"unitTests,omitempty"`

	// IntegrationTests describes integration tests.
	IntegrationTests []string `json:"integrationTests,omitempty"`

	// SecurityTests describes security-specific tests.
	SecurityTests []string `json:"securityTests,omitempty"`

	// RegressionTests describes tests to prevent regression.
	RegressionTests []string `json:"regressionTests,omitempty"`

	// ManualTests describes manual testing procedures.
	ManualTests []string `json:"manualTests,omitempty"`

	// TestRefs links to app-test-spec test cases for automated validation.
	TestRefs []TestReference `json:"testRefs,omitempty"`

	// AcceptanceCriteria defines what constitutes a successful fix.
	AcceptanceCriteria []string `json:"acceptanceCriteria,omitempty"`

	// Tools lists testing tools useful for validation.
	Tools []string `json:"tools,omitempty"`
}
