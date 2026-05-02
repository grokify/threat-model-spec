package ir

import "github.com/invopop/jsonschema"

// TestPurpose indicates the purpose of a test case reference.
type TestPurpose string

const (
	// TestPurposeExploitation indicates a test that validates exploitation.
	TestPurposeExploitation TestPurpose = "exploitation"

	// TestPurposeDetection indicates a test that validates detection works.
	TestPurposeDetection TestPurpose = "detection"

	// TestPurposeRemediation indicates a test that validates a fix is effective.
	TestPurposeRemediation TestPurpose = "remediation"

	// TestPurposeRegression indicates a test that prevents vulnerability return.
	TestPurposeRegression TestPurpose = "regression"
)

// JSONSchema implements jsonschema.JSONSchemaer for TestPurpose.
func (TestPurpose) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"exploitation", "detection", "remediation", "regression"},
	}
}

// TestReference links a threat model component to an app-test-spec test case.
// This enables bidirectional references between threat models and executable tests.
type TestReference struct {
	// TestID is the unique identifier of the test case in app-test-spec.
	TestID string `json:"testId"`

	// TestFile is the path to the app-test-spec test file.
	TestFile string `json:"testFile,omitempty"`

	// Purpose indicates the test's purpose (exploitation, detection, remediation, regression).
	Purpose TestPurpose `json:"purpose"`

	// Description provides context about what this test validates.
	Description string `json:"description,omitempty"`

	// SuiteID is the test suite this test belongs to.
	SuiteID string `json:"suiteId,omitempty"`

	// AttackStep links this test to a specific attack step number.
	AttackStep int `json:"attackStep,omitempty"`

	// Automated indicates if this test can run automatically in CI/CD.
	Automated bool `json:"automated,omitempty"`

	// Tool specifies the test runner (e.g., "agent-dast", "nuclei", "custom").
	Tool string `json:"tool,omitempty"`
}

// TestSuiteReference links a threat model to an app-test-spec test suite.
type TestSuiteReference struct {
	// SuiteID is the unique identifier of the test suite.
	SuiteID string `json:"suiteId"`

	// SuiteFile is the path to the app-test-spec test suite file.
	SuiteFile string `json:"suiteFile,omitempty"`

	// Description provides context about this test suite.
	Description string `json:"description,omitempty"`

	// Tests lists the individual test references within this suite.
	Tests []TestReference `json:"tests,omitempty"`

	// Tags are metadata tags for filtering test suites.
	Tags []string `json:"tags,omitempty"`

	// CIEnabled indicates if this suite runs in CI/CD pipelines.
	CIEnabled bool `json:"ciEnabled,omitempty"`
}
