package schema

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion == "" {
		t.Fatal("SchemaVersion is empty")
	}
	if !strings.HasPrefix(SchemaVersion, "v") {
		t.Errorf("SchemaVersion = %q, want a version string prefixed with %q", SchemaVersion, "v")
	}
}

func TestEmbeddedSchemasAreValidJSONSchema(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"ThreatModelSchema", ThreatModelSchema},
		{"DiagramSchema", DiagramSchema},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.data) == 0 {
				t.Fatal("embedded schema is empty")
			}

			var parsed map[string]any
			if err := json.Unmarshal(tt.data, &parsed); err != nil {
				t.Fatalf("embedded schema is not valid JSON: %v", err)
			}

			if _, ok := parsed["$schema"]; !ok {
				t.Error("embedded schema is missing $schema")
			}
			if _, ok := parsed["$id"]; !ok {
				t.Error("embedded schema is missing $id")
			}
			if _, ok := parsed["$defs"]; !ok {
				t.Error("embedded schema is missing $defs")
			}
		})
	}
}

// TestEmbeddedSchemasMatchDisk guards against the embed going stale relative
// to the generated schema files sitting alongside it in this package
// (this repo has real prior instances of docs/generated output drifting from
// source — this test exists to catch that class of bug for the embed itself).
func TestEmbeddedSchemasMatchDisk(t *testing.T) {
	tests := []struct {
		name     string
		embedded []byte
		diskPath string
	}{
		{"ThreatModelSchema", ThreatModelSchema, "threat-model.schema.json"},
		{"DiagramSchema", DiagramSchema, "diagram.schema.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			onDisk, err := os.ReadFile(tt.diskPath)
			if err != nil {
				t.Fatalf("reading %s: %v", tt.diskPath, err)
			}
			if string(tt.embedded) != string(onDisk) {
				t.Errorf("embedded %s does not match %s on disk; regenerate via cmd/genschema", tt.name, tt.diskPath)
			}
		})
	}
}

// TestSchemaIDsAreResolvable confirms schema $id values point at the published
// documentation site rather than the github.com web UI, which serves an HTML
// wrapper instead of raw JSON and is not usable as a $schema reference.
func TestSchemaIDsAreResolvable(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"ThreatModelSchema", ThreatModelSchema},
		{"DiagramSchema", DiagramSchema},
	}

	const validHost = "https://grokify.github.io/threat-model-spec/"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parsed struct {
				ID string `json:"$id"`
			}
			if err := json.Unmarshal(tt.data, &parsed); err != nil {
				t.Fatalf("unmarshaling schema: %v", err)
			}
			if !strings.HasPrefix(parsed.ID, validHost) {
				t.Errorf("$id = %q, want prefix %q", parsed.ID, validHost)
			}
			if !strings.Contains(parsed.ID, SchemaVersion) {
				t.Errorf("$id = %q, does not contain SchemaVersion %q", parsed.ID, SchemaVersion)
			}
		})
	}
}
