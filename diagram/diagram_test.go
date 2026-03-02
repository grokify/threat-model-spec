package diagram

import (
	"strings"
	"testing"

	"github.com/grokify/threat-model-spec/stride"
)

func TestNewDiagram(t *testing.T) {
	d := New("Test Diagram")

	if d.Title != "Test Diagram" {
		t.Errorf("New().Title = %v, want %v", d.Title, "Test Diagram")
	}

	if d.Direction != DirectionRight {
		t.Errorf("New().Direction = %v, want %v", d.Direction, DirectionRight)
	}

	if len(d.Boundaries) != 0 {
		t.Errorf("New().Boundaries length = %v, want 0", len(d.Boundaries))
	}

	if len(d.Elements) != 0 {
		t.Errorf("New().Elements length = %v, want 0", len(d.Elements))
	}

	if len(d.Flows) != 0 {
		t.Errorf("New().Flows length = %v, want 0", len(d.Flows))
	}
}

func TestAddBoundary(t *testing.T) {
	d := New("Test")
	b := d.AddBoundary("browser", "Browser Sandbox", BrowserBoundary)

	if b.ID != "browser" {
		t.Errorf("AddBoundary().ID = %v, want %v", b.ID, "browser")
	}

	if b.Type != BrowserBoundary {
		t.Errorf("AddBoundary().Type = %v, want %v", b.Type, BrowserBoundary)
	}

	if len(d.Boundaries) != 1 {
		t.Errorf("Boundaries length = %v, want 1", len(d.Boundaries))
	}
}

func TestAddElement(t *testing.T) {
	d := New("Test")
	e := d.AddElement("gateway", "OpenClaw Gateway", Gateway, "localhost")

	if e.ID != "gateway" {
		t.Errorf("AddElement().ID = %v, want %v", e.ID, "gateway")
	}

	if e.Type != Gateway {
		t.Errorf("AddElement().Type = %v, want %v", e.Type, Gateway)
	}

	if e.ParentID != "localhost" {
		t.Errorf("AddElement().ParentID = %v, want %v", e.ParentID, "localhost")
	}

	if e.FullID() != "localhost.gateway" {
		t.Errorf("Element.FullID() = %v, want %v", e.FullID(), "localhost.gateway")
	}
}

func TestAddFlow(t *testing.T) {
	d := New("Test")
	f := d.AddFlow("browser.js", "localhost.gateway", "WebSocket", AttackFlow)

	if f.From != "browser.js" {
		t.Errorf("AddFlow().From = %v, want %v", f.From, "browser.js")
	}

	if f.Type != AttackFlow {
		t.Errorf("AddFlow().Type = %v, want %v", f.Type, AttackFlow)
	}

	if !f.IsAttack() {
		t.Error("AttackFlow.IsAttack() should return true")
	}
}

func TestAddAttackFlow(t *testing.T) {
	d := New("Test")
	f := d.AddAttackFlow("browser", "gateway", "WebSocket to localhost", 3)

	if f.Step != 3 {
		t.Errorf("AddAttackFlow().Step = %v, want %v", f.Step, 3)
	}

	if f.Type != AttackFlow {
		t.Errorf("AddAttackFlow().Type = %v, want %v", f.Type, AttackFlow)
	}
}

func TestElementsInBoundary(t *testing.T) {
	d := New("Test")
	d.AddBoundary("browser", "Browser", BrowserBoundary)
	d.AddElement("victim", "Victim", Browser, "browser")
	d.AddElement("js", "Malicious JS", Process, "browser")
	d.AddElement("gateway", "Gateway", Gateway, "localhost")

	elements := d.ElementsInBoundary("browser")
	if len(elements) != 2 {
		t.Errorf("ElementsInBoundary() returned %v elements, want 2", len(elements))
	}
}

func TestAttackFlows(t *testing.T) {
	d := New("Test")
	d.AddFlow("a", "b", "normal", NormalFlow)
	d.AddFlow("b", "c", "attack", AttackFlow)
	d.AddFlow("c", "d", "exfil", ExfilFlow)

	attacks := d.AttackFlows()
	if len(attacks) != 2 {
		t.Errorf("AttackFlows() returned %v flows, want 2", len(attacks))
	}
}

func TestFlowsWithSTRIDE(t *testing.T) {
	d := New("Test")
	d.AddFlow("a", "b", "normal", NormalFlow)

	f := d.AddFlow("b", "c", "attack", AttackFlow)
	f.Threats = []stride.Threat{{Type: stride.Spoofing, Title: "Test"}}

	flows := d.FlowsWithSTRIDE()
	if len(flows) != 1 {
		t.Errorf("FlowsWithSTRIDE() returned %v flows, want 1", len(flows))
	}
}

func TestRenderBasic(t *testing.T) {
	d := New("Test Diagram")
	d.AddBoundary("browser", "Browser Sandbox", BrowserBoundary)
	d.AddElement("victim", "Victim Browser", Browser, "browser")
	d.AddElement("gateway", "Gateway", Gateway, "")
	d.AddFlow("browser.victim", "gateway", "connects", NormalFlow)

	r := NewRenderer()
	output := r.Render(d)

	// Check basic structure
	if !strings.Contains(output, "# Test Diagram") {
		t.Error("Output should contain title comment")
	}

	if !strings.Contains(output, "direction: right") {
		t.Error("Output should contain direction")
	}

	if !strings.Contains(output, "browser: Browser Sandbox") {
		t.Error("Output should contain boundary declaration")
	}

	if !strings.Contains(output, "victim: Victim Browser") {
		t.Error("Output should contain element declaration")
	}

	if !strings.Contains(output, "browser.victim -> gateway") {
		t.Error("Output should contain flow")
	}
}

func TestRenderAttackFlow(t *testing.T) {
	d := New("Attack Test")
	d.AddFlow("attacker", "victim", "exploit", AttackFlow)

	r := NewRenderer()
	output := r.Render(d)

	if !strings.Contains(output, "stroke: \"#c62828\"") {
		t.Error("Attack flow should have red stroke")
	}

	if !strings.Contains(output, "stroke-dash: 3") {
		t.Error("Attack flow should be dashed")
	}
}

func TestRenderThreat(t *testing.T) {
	d := New("Threat Test")
	d.AddThreat(stride.Threat{
		Type:      stride.Spoofing,
		Title:     "Localhost spoofing",
		ElementID: "gateway",
	})

	r := NewRenderer()
	output := r.Render(d)

	if !strings.Contains(output, "threat-S-gateway") {
		t.Error("Output should contain threat ID")
	}

	if !strings.Contains(output, "S - Localhost spoofing") {
		t.Error("Output should contain threat label")
	}
}

func TestElementTypeD2Shape(t *testing.T) {
	tests := []struct {
		elementType ElementType
		want        string
	}{
		{Process, "rectangle"},
		{DataStore, "cylinder"},
		{Database, "cylinder"},
		{ExternalEntity, "person"},
		{Gateway, "hexagon"},
		{Browser, "rectangle"},
	}

	for _, tt := range tests {
		t.Run(string(tt.elementType), func(t *testing.T) {
			if got := tt.elementType.D2Shape(); got != tt.want {
				t.Errorf("ElementType.D2Shape() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBoundaryGetEffectiveType(t *testing.T) {
	b := Boundary{
		ID:       "test",
		Type:     InternalBoundary,
		Breached: true,
	}

	if b.GetEffectiveType() != BreachedBoundary {
		t.Errorf("GetEffectiveType() = %v, want %v", b.GetEffectiveType(), BreachedBoundary)
	}

	b.Breached = false
	if b.GetEffectiveType() != InternalBoundary {
		t.Errorf("GetEffectiveType() = %v, want %v", b.GetEffectiveType(), InternalBoundary)
	}
}

func TestStyleMerge(t *testing.T) {
	s1 := &Style{
		Fill:   "#ffffff",
		Stroke: "#000000",
	}

	s2 := &Style{
		Stroke: "#ff0000",
	}

	merged := s1.Merge(s2)

	if merged.Fill != "#ffffff" {
		t.Errorf("Merge().Fill = %v, want %v", merged.Fill, "#ffffff")
	}

	if merged.Stroke != "#ff0000" {
		t.Errorf("Merge().Stroke = %v, want %v", merged.Stroke, "#ff0000")
	}
}
