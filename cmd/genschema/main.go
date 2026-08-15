// Command genschema generates JSON Schema files from Go types.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/grokify/threat-model-spec/ir"
	"github.com/invopop/jsonschema"
)

const (
	// baseURL is the published documentation site, which serves the schema
	// files under docs/versions/ as static assets (see mkdocs.yml site_url).
	// The github.com web UI does not serve raw JSON, so it cannot be used here.
	baseURL        = "https://grokify.github.io/threat-model-spec"
	currentVersion = "v0.7.0"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: genschema <output-dir> [version]")
		fmt.Fprintln(os.Stderr, "  output-dir: Directory to write schema files")
		fmt.Fprintln(os.Stderr, "  version:    Schema version (default: "+currentVersion+")")
		os.Exit(1)
	}

	outputDir := os.Args[1]
	version := currentVersion
	if len(os.Args) >= 3 {
		version = os.Args[2]
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate schema for ThreatModel (the canonical multi-diagram format)
	if err := generateSchema(outputDir, "threat-model.schema.json", version, &ir.ThreatModel{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating ThreatModel schema: %v\n", err)
		os.Exit(1)
	}

	// Generate schema for DiagramIR (single-diagram format for backward compatibility)
	if err := generateSchema(outputDir, "diagram.schema.json", version, &ir.DiagramIR{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating DiagramIR schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Schema files generated successfully:")
	fmt.Printf("  - %s/threat-model.schema.json\n", outputDir)
	fmt.Printf("  - %s/diagram.schema.json\n", outputDir)
	fmt.Printf("  - Schema version: %s\n", version)
}

func generateSchema(outputDir, filename, version string, v any) error {
	reflector := &jsonschema.Reflector{
		DoNotReference: false,
		ExpandedStruct: false,
	}

	schema := reflector.Reflect(v)
	// Use versioned URL: https://grokify.github.io/threat-model-spec/versions/v0.7.0/threat-model.schema.json
	schema.ID = jsonschema.ID(fmt.Sprintf("%s/versions/%s/%s", baseURL, version, filename))

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling schema: %w", err)
	}

	outputPath := filepath.Join(outputDir, filename)
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing schema file: %w", err)
	}

	return nil
}
