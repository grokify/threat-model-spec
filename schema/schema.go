// Package schema provides embedded JSON Schema files for threat model validation.
package schema

import (
	_ "embed"
)

// ThreatModelSchema is the JSON Schema for the ThreatModel type (multi-diagram format).
//
//go:embed threat-model.schema.json
var ThreatModelSchema []byte

// DiagramSchema is the JSON Schema for the DiagramIR type (single-diagram format).
//
//go:embed diagram.schema.json
var DiagramSchema []byte
