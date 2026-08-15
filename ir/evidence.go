package ir

import "github.com/invopop/jsonschema"

// EvidenceLocatorType identifies which locator variant of EvidenceLocator
// is populated.
type EvidenceLocatorType string

const (
	// EvidenceLocatorTypeFile locates evidence at a path and line range in
	// a source tree.
	EvidenceLocatorTypeFile EvidenceLocatorType = "file"

	// EvidenceLocatorTypeDocument locates evidence at a URI and section
	// within a document artifact.
	EvidenceLocatorTypeDocument EvidenceLocatorType = "document"

	// EvidenceLocatorTypeConfig locates evidence at a path and key within a
	// configuration or manifest file.
	EvidenceLocatorTypeConfig EvidenceLocatorType = "config"

	// EvidenceLocatorTypeQuery locates evidence via a query against an
	// external data source (e.g. SIEM, logs) over a time window.
	EvidenceLocatorTypeQuery EvidenceLocatorType = "query"

	// EvidenceLocatorTypeURL locates evidence at an observed URL (e.g. a
	// live endpoint response).
	EvidenceLocatorTypeURL EvidenceLocatorType = "url"
)

// JSONSchema implements jsonschema.JSONSchemaer for EvidenceLocatorType.
func (EvidenceLocatorType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"file", "document", "config", "query", "url"},
	}
}

// EvidenceLocator is a tagged union pointing at the specific place evidence
// was drawn from. Exactly one field group should be populated, matching
// Type:
//
//	file:     Path, StartLine, EndLine
//	document: URI, Section
//	config:   Path, KeyPath
//	query:    DataSource, Query, TimeWindow
//	url:      URL, ObservedAt
type EvidenceLocator struct {
	// Type selects which of the field groups below is populated.
	Type EvidenceLocatorType `json:"type"`

	// Path is the file path, used by "file" and "config" locators.
	Path string `json:"path,omitempty"`

	// StartLine is the first line of the referenced range, used by "file" locators.
	StartLine int `json:"startLine,omitempty"`

	// EndLine is the last line of the referenced range, used by "file" locators.
	EndLine int `json:"endLine,omitempty"`

	// URI is the document location, used by "document" locators.
	URI string `json:"uri,omitempty"`

	// Section is the section within the document, used by "document" locators.
	Section string `json:"section,omitempty"`

	// KeyPath is the key within the config file, used by "config" locators.
	KeyPath string `json:"keyPath,omitempty"`

	// DataSource identifies the external system queried, used by "query" locators.
	DataSource string `json:"dataSource,omitempty"`

	// Query is the query executed, used by "query" locators.
	Query string `json:"query,omitempty"`

	// TimeWindow is the time range the query covered, used by "query" locators.
	TimeWindow string `json:"timeWindow,omitempty"`

	// URL is the observed URL, used by "url" locators.
	URL string `json:"url,omitempty"`

	// ObservedAt is when the URL was observed (RFC 3339), used by "url" locators.
	ObservedAt string `json:"observedAt,omitempty"`
}

// Evidence is inspectable material a Finding, ArchitectureAssertion, or
// SecurityRequirement cites in support of a claim. Evidence separates the
// source of truth (this object) from the interpretation built on it
// (Finding, ArchitectureAssertion), so agent-generated interpretation can
// never be confused with the underlying material.
type Evidence struct {
	// ID is the unique identifier for this evidence.
	ID string `json:"id"`

	// ArtifactID references the Artifact this evidence was extracted from.
	ArtifactID string `json:"artifactId,omitempty"`

	// Locator points at the specific place within the artifact.
	Locator EvidenceLocator `json:"locator"`

	// Digest is a content hash of the referenced material, for integrity
	// checking as the underlying artifact changes.
	Digest string `json:"digest,omitempty"`

	// Excerpt is a small relevant excerpt of the evidence, kept short
	// enough to review inline without embedding the full artifact.
	Excerpt string `json:"excerpt,omitempty"`

	// Summary is a one-line human-readable description of what this
	// evidence shows.
	Summary string `json:"summary,omitempty"`
}
