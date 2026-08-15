package ir

import (
	"encoding/json"
	"testing"
)

func TestEvidenceLocatorType_JSONSchema(t *testing.T) {
	schema := EvidenceLocatorType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("expected 5 enum values, got %d", len(schema.Enum))
	}
}

func TestEvidence_JSON_FileLocator(t *testing.T) {
	e := Evidence{
		ID:         "evidence-authz-42",
		ArtifactID: "artifact-code-1",
		Locator: EvidenceLocator{
			Type:      EvidenceLocatorTypeFile,
			Path:      "src/orders/handler.go",
			StartLine: 81,
			EndLine:   97,
		},
		Digest:  "sha256:abc123",
		Excerpt: "func (h *Handler) GetOrder(id string) {",
		Summary: "Order lookup uses object ID without tenant constraint",
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Evidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Locator.Type != EvidenceLocatorTypeFile {
		t.Errorf("Locator.Type = %q, want %q", decoded.Locator.Type, EvidenceLocatorTypeFile)
	}
	if decoded.Locator.Path != e.Locator.Path {
		t.Errorf("Locator.Path = %q, want %q", decoded.Locator.Path, e.Locator.Path)
	}
	if decoded.Locator.StartLine != 81 {
		t.Errorf("Locator.StartLine = %d, want 81", decoded.Locator.StartLine)
	}
}

func TestEvidence_JSON_QueryLocator(t *testing.T) {
	e := Evidence{
		ID: "evidence-siem-1",
		Locator: EvidenceLocator{
			Type:       EvidenceLocatorTypeQuery,
			DataSource: "splunk",
			Query:      "index=ws origin!=trusted.example.com",
			TimeWindow: "2026-08-01T00:00:00Z/2026-08-02T00:00:00Z",
		},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Evidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Locator.DataSource != "splunk" {
		t.Errorf("Locator.DataSource = %q, want %q", decoded.Locator.DataSource, "splunk")
	}
	if decoded.Locator.Query != e.Locator.Query {
		t.Errorf("Locator.Query mismatch")
	}
}

func TestEvidence_Fields(t *testing.T) {
	e := Evidence{
		ID: "evidence-1",
		Locator: EvidenceLocator{
			Type: EvidenceLocatorTypeURL,
			URL:  "https://example.com/api/admin",
		},
	}
	if e.ID != "evidence-1" {
		t.Errorf("ID = %q, want %q", e.ID, "evidence-1")
	}
	if e.Locator.Type != EvidenceLocatorTypeURL {
		t.Errorf("Locator.Type = %q, want %q", e.Locator.Type, EvidenceLocatorTypeURL)
	}
}
