// Package examples validates that every canonical example ThreatModel in this
// directory stays schema-valid and internally consistent as the ir package evolves.
package examples

import (
	"path/filepath"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func TestExamplesValidate(t *testing.T) {
	paths, err := filepath.Glob("*.json")
	if err != nil {
		t.Fatalf("globbing examples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no example JSON files found in examples/")
	}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			tm, err := ir.LoadThreatModelFromFile(path)
			if err != nil {
				t.Fatalf("loading %s: %v", path, err)
			}
			if err := tm.Validate(); err != nil {
				t.Fatalf("validating %s: %v", path, err)
			}
			for i, dv := range tm.Diagrams {
				d := dv.ToDiagramIR(tm)
				if err := d.ValidateStrict(); err != nil {
					t.Errorf("strict-validating %s diagrams[%d] (%s): %v", path, i, dv.Type, err)
				}
			}
		})
	}
}
