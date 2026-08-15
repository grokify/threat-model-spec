package stix

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

// loadDiagram loads the flagship example ThreatModel and returns its first
// diagram converted to a DiagramIR, matching cmd/tms's loadInput pattern.
func loadDiagram(t *testing.T) *ir.DiagramIR {
	t.Helper()
	tm, err := ir.LoadThreatModelFromFile("../examples/openclaw-websocket-takeover.json")
	if err != nil {
		t.Fatalf("loading example threat model: %v", err)
	}
	if len(tm.Diagrams) == 0 {
		t.Fatal("example threat model has no diagrams")
	}
	return tm.Diagrams[0].ToDiagramIR(tm)
}

func TestNewExporter(t *testing.T) {
	e := NewExporter()
	if e.IdentityName != "Threat Model Spec" {
		t.Errorf("IdentityName = %q, want %q", e.IdentityName, "Threat Model Spec")
	}
	if e.IdentityClass != "organization" {
		t.Errorf("IdentityClass = %q, want %q", e.IdentityClass, "organization")
	}
}

func TestExportDFD(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile("../examples/openclaw-websocket-takeover.json")
	if err != nil {
		t.Fatalf("loading example threat model: %v", err)
	}

	var dfd *ir.DiagramIR
	for _, dv := range tm.Diagrams {
		if dv.Type == ir.DiagramTypeDFD {
			d := dv.ToDiagramIR(tm)
			dfd = d
			break
		}
	}
	if dfd == nil {
		t.Fatal("example threat model has no DFD diagram")
	}

	e := NewExporter()
	bundle, err := e.Export(dfd)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	if bundle.Type != "bundle" {
		t.Errorf("bundle.Type = %q, want %q", bundle.Type, "bundle")
	}
	if !strings.HasPrefix(bundle.ID, "bundle--") {
		t.Errorf("bundle.ID = %q, want prefix %q", bundle.ID, "bundle--")
	}
	if len(bundle.Objects) == 0 {
		t.Fatal("bundle has no objects")
	}

	// First object is always the identity used for created_by_ref.
	identity, ok := bundle.Objects[0].(*Identity)
	if !ok {
		t.Fatalf("bundle.Objects[0] = %T, want *Identity", bundle.Objects[0])
	}
	if identity.Type != "identity" || identity.SpecVersion != "2.1" {
		t.Errorf("identity = %+v, want type=identity spec_version=2.1", identity)
	}

	// DFD elements become Infrastructure objects; framework mappings on this
	// diagram (STRIDE only has no dedicated STIX type, but CWE/OWASP/ATT&CK do).
	var sawInfra bool
	for _, obj := range bundle.Objects {
		if _, ok := obj.(*Infrastructure); ok {
			sawInfra = true
		}
	}
	if !sawInfra {
		t.Error("expected at least one Infrastructure object from DFD elements")
	}
}

func TestExportAttackChain(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile("../examples/openclaw-websocket-takeover.json")
	if err != nil {
		t.Fatalf("loading example threat model: %v", err)
	}

	var attackChain *ir.DiagramIR
	for _, dv := range tm.Diagrams {
		if dv.Type == ir.DiagramTypeAttack {
			attackChain = dv.ToDiagramIR(tm)
			break
		}
	}
	if attackChain == nil {
		t.Fatal("example threat model has no attack-chain diagram")
	}

	e := NewExporter()
	bundle, err := e.Export(attackChain)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var sawAttackPattern, sawThreatActor, sawIndicator bool
	for _, obj := range bundle.Objects {
		switch o := obj.(type) {
		case *AttackPattern:
			sawAttackPattern = true
			if o.Type != "attack-pattern" {
				t.Errorf("AttackPattern.Type = %q, want %q", o.Type, "attack-pattern")
			}
		case *ThreatActor:
			sawThreatActor = true
			if len(o.ThreatActorTypes) == 0 {
				t.Error("ThreatActor.ThreatActorTypes is empty")
			}
		case *Indicator:
			sawIndicator = true
			if o.Pattern == "" || o.PatternType != "stix" {
				t.Errorf("Indicator = %+v, want non-empty pattern and pattern_type=stix", o)
			}
		}
	}

	// The flagship example's attack-chain diagram has attacker (external-entity,
	// mapped to ThreatActor), attack steps (mapped to AttackPattern), and a
	// target (mapped to Indicator).
	if !sawAttackPattern {
		t.Error("expected at least one AttackPattern object from attack steps")
	}
	if !sawThreatActor {
		t.Error("expected at least one ThreatActor object from the external-entity attacker element")
	}
	if !sawIndicator {
		t.Error("expected at least one Indicator object from targets")
	}
}

func TestExportMappings(t *testing.T) {
	d := loadDiagram(t)
	e := NewExporter()
	bundle, err := e.Export(d)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var sawVulnerability, sawMappingAttackPattern bool
	for _, obj := range bundle.Objects {
		switch o := obj.(type) {
		case *Vulnerability:
			sawVulnerability = true
			// The example maps CWE-346; confirm it round-trips into an
			// external reference rather than being silently dropped.
			var sawCWERef bool
			for _, ref := range o.ExternalReferences {
				if ref.SourceName == "cwe" {
					sawCWERef = true
					if ref.ExternalID != "CWE-346" {
						t.Errorf("cwe external_id = %q, want %q", ref.ExternalID, "CWE-346")
					}
				}
			}
			if !sawCWERef {
				t.Error("Vulnerability has no cwe external reference")
			}
		case *AttackPattern:
			for _, ref := range o.ExternalReferences {
				if ref.SourceName == "mitre-attack" || ref.SourceName == "owasp-api" {
					sawMappingAttackPattern = true
				}
			}
		}
	}

	if !sawVulnerability {
		t.Error("expected a Vulnerability object from the CWE-346 mapping")
	}
	if !sawMappingAttackPattern {
		t.Error("expected an AttackPattern from MITRE ATT&CK or OWASP mappings")
	}
}

func TestExportMitigationsToCourseOfAction(t *testing.T) {
	d := loadDiagram(t)
	e := NewExporter()
	bundle, err := e.Export(d)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	if len(d.Mitigations) == 0 {
		t.Fatal("example diagram has no mitigations to exercise this path")
	}

	var coaCount int
	for _, obj := range bundle.Objects {
		if _, ok := obj.(*CourseOfAction); ok {
			coaCount++
		}
	}
	if coaCount != len(d.Mitigations) {
		t.Errorf("got %d CourseOfAction objects, want %d (one per mitigation)", coaCount, len(d.Mitigations))
	}
}

func TestExportJSON(t *testing.T) {
	d := loadDiagram(t)
	e := NewExporter()

	out, err := e.ExportJSON(d)
	if err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}
	if out == "" {
		t.Fatal("ExportJSON() returned empty string")
	}

	// Must be valid JSON and a well-formed STIX 2.1 bundle envelope.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("ExportJSON() output is not valid JSON: %v", err)
	}
	if parsed["type"] != "bundle" {
		t.Errorf("parsed[type] = %v, want %q", parsed["type"], "bundle")
	}
	id, _ := parsed["id"].(string)
	if !strings.HasPrefix(id, "bundle--") {
		t.Errorf("parsed[id] = %q, want prefix %q", id, "bundle--")
	}
	objects, ok := parsed["objects"].([]any)
	if !ok || len(objects) == 0 {
		t.Fatal("parsed[objects] is missing or empty")
	}

	// Every object in a STIX 2.1 bundle must carry type, id, and spec_version.
	for i, raw := range objects {
		obj, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("objects[%d] is not a JSON object", i)
		}
		if obj["type"] == nil || obj["type"] == "" {
			t.Errorf("objects[%d] missing type", i)
		}
		if obj["id"] == nil || obj["id"] == "" {
			t.Errorf("objects[%d] missing id", i)
		}
		if obj["spec_version"] != "2.1" {
			t.Errorf("objects[%d] spec_version = %v, want %q", i, obj["spec_version"], "2.1")
		}
	}
}

// TestExportEmptyDiagram exercises the edge case of a diagram with no
// threat actors, mitigations, threats, or mappings — export must still
// succeed cleanly (identity object only) rather than error or panic.
func TestExportEmptyDiagram(t *testing.T) {
	d := &ir.DiagramIR{
		Type:  ir.DiagramTypeDFD,
		Title: "Empty Diagram",
	}

	e := NewExporter()
	bundle, err := e.Export(d)
	if err != nil {
		t.Fatalf("Export() on empty diagram error = %v", err)
	}
	if len(bundle.Objects) != 1 {
		t.Fatalf("got %d objects for an empty diagram, want 1 (identity only)", len(bundle.Objects))
	}
	if _, ok := bundle.Objects[0].(*Identity); !ok {
		t.Fatalf("bundle.Objects[0] = %T, want *Identity", bundle.Objects[0])
	}

	out, err := e.ExportJSON(d)
	if err != nil {
		t.Fatalf("ExportJSON() on empty diagram error = %v", err)
	}
	if out == "" {
		t.Fatal("ExportJSON() on empty diagram returned empty string")
	}
}

// TestExportSequenceDiagram exercises the sequence-diagram export path,
// which is not covered by the flagship example (it only has dfd/attack-chain).
func TestExportSequenceDiagram(t *testing.T) {
	d := &ir.DiagramIR{
		Type:  ir.DiagramTypeSequence,
		Title: "Sequence Diagram",
		Actors: []ir.Actor{
			{ID: "attacker", Label: "Attacker", Malicious: true},
			{ID: "victim", Label: "Victim"},
		},
		Messages: []ir.Message{
			{From: "attacker", To: "victim", Label: "Phishing email", Type: ir.FlowTypeAttack},
			{From: "victim", To: "attacker", Label: "Credentials", Type: ir.FlowTypeExfil},
		},
	}

	e := NewExporter()
	bundle, err := e.Export(d)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var sawThreatActor, sawAttackPattern int
	for _, obj := range bundle.Objects {
		switch obj.(type) {
		case *ThreatActor:
			sawThreatActor++
		case *AttackPattern:
			sawAttackPattern++
		}
	}
	if sawThreatActor != 1 {
		t.Errorf("got %d ThreatActor objects, want 1 (only the malicious actor)", sawThreatActor)
	}
	if sawAttackPattern != 2 {
		t.Errorf("got %d AttackPattern objects, want 2 (attack + exfil messages)", sawAttackPattern)
	}
}

// TestAddObjectNilSkipped confirms AddObject silently drops nil objects,
// matching the flowToRelationship/attackToRelationship stubs that currently
// always return nil.
func TestAddObjectNilSkipped(t *testing.T) {
	b := NewBundle()
	b.AddObject(nil)
	if len(b.Objects) != 0 {
		t.Errorf("AddObject(nil) added an object; got %d objects, want 0", len(b.Objects))
	}
}
