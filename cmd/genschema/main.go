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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: genschema <output-dir>")
		os.Exit(1)
	}

	outputDir := os.Args[1]
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate schema for ThreatModel (the canonical multi-diagram format)
	if err := generateSchema(outputDir, "threat-model.schema.json", &ir.ThreatModel{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating ThreatModel schema: %v\n", err)
		os.Exit(1)
	}

	// Generate schema for DiagramIR (single-diagram format for backward compatibility)
	if err := generateSchema(outputDir, "diagram.schema.json", &ir.DiagramIR{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating DiagramIR schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Schema files generated successfully:")
	fmt.Printf("  - %s/threat-model.schema.json\n", outputDir)
	fmt.Printf("  - %s/diagram.schema.json\n", outputDir)
}

func generateSchema(outputDir, filename string, v any) error {
	reflector := &jsonschema.Reflector{
		DoNotReference: false,
		ExpandedStruct: false,
	}

	schema := reflector.Reflect(v)
	schema.ID = jsonschema.ID("https://github.com/grokify/threat-model-spec/schema/" + filename)

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
