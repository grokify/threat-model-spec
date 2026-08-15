package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func TestGenerateSchemaThreatModel(t *testing.T) {
	dir := t.TempDir()

	if err := generateSchema(dir, "threat-model.schema.json", "v9.9.9", &ir.ThreatModel{}); err != nil {
		t.Fatalf("generateSchema: %v", err)
	}

	path := filepath.Join(dir, "threat-model.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated schema: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("generated schema is empty")
	}

	var parsed struct {
		ID     string         `json:"$id"`
		Schema string         `json:"$schema"`
		Defs   map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generated schema is not valid JSON: %v", err)
	}

	wantID := "https://grokify.github.io/threat-model-spec/versions/v9.9.9/threat-model.schema.json"
	if parsed.ID != wantID {
		t.Errorf("$id = %q, want %q", parsed.ID, wantID)
	}
	if parsed.Schema == "" {
		t.Error("$schema is empty")
	}
	if len(parsed.Defs) == 0 {
		t.Error("$defs is empty")
	}
}

func TestGenerateSchemaDiagramIR(t *testing.T) {
	dir := t.TempDir()

	if err := generateSchema(dir, "diagram.schema.json", "v9.9.9", &ir.DiagramIR{}); err != nil {
		t.Fatalf("generateSchema: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "diagram.schema.json"))
	if err != nil {
		t.Fatalf("reading generated schema: %v", err)
	}

	var parsed struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generated schema is not valid JSON: %v", err)
	}
	if !strings.HasSuffix(parsed.ID, "diagram.schema.json") {
		t.Errorf("$id = %q, want suffix %q", parsed.ID, "diagram.schema.json")
	}
}

// TestGenerateSchemaUsesResolvableBaseURL guards against regressing to a
// $id host that doesn't serve raw JSON (github.com's web UI serves an HTML
// wrapper; only the published docs site does) — this repo shipped that bug
// in earlier versions before it was fixed.
func TestGenerateSchemaUsesResolvableBaseURL(t *testing.T) {
	dir := t.TempDir()
	if err := generateSchema(dir, "threat-model.schema.json", currentVersion, &ir.ThreatModel{}); err != nil {
		t.Fatalf("generateSchema: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "threat-model.schema.json"))
	if err != nil {
		t.Fatalf("reading generated schema: %v", err)
	}

	var parsed struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generated schema is not valid JSON: %v", err)
	}

	const badHost = "https://github.com/grokify/threat-model-spec"
	if strings.HasPrefix(parsed.ID, badHost) {
		t.Errorf("$id = %q uses the non-resolvable github.com web UI host", parsed.ID)
	}
	const goodHost = "https://grokify.github.io/threat-model-spec"
	if !strings.HasPrefix(parsed.ID, goodHost) {
		t.Errorf("$id = %q, want prefix %q", parsed.ID, goodHost)
	}
}
