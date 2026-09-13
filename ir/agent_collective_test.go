package ir

import "testing"

func TestAgentCollectiveRoundTrip(t *testing.T) {
	tm := &ThreatModel{
		ID:    "tm-collective",
		Title: "Collective",
		Diagrams: []DiagramView{
			{
				Type:      DiagramTypeDFD,
				Direction: DirectionRight,
				Elements: []Element{
					{ID: "agent-a", Label: "Agent A", Type: ElementTypeAgent},
					{ID: "agent-b", Label: "Agent B", Type: ElementTypeAgent},
				},
				Flows: []Flow{
					{From: "agent-a", To: "agent-b", Label: "coordinate", Type: FlowTypeCoordination},
				},
			},
		},
		AgentCollectives: []AgentCollective{
			{
				ID:                  "collective-1",
				Name:                "Swarm",
				Population:          200,
				CoordinationChannel: "directory-name message board",
				Emergent:            true,
				EmergentBehaviors:   []string{"mailbox", "signing"},
				RewardHacking: &RewardHacking{
					Objective:          "pass grader",
					UnintendedPath:     "game the grader",
					ImpossibleTaskRate: 0.3,
				},
			},
		},
	}

	if err := tm.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if len(tm.AgentCollectives) != 1 {
		t.Fatalf("AgentCollectives len = %d, want 1", len(tm.AgentCollectives))
	}
	if tm.AgentCollectives[0].RewardHacking.ImpossibleTaskRate != 0.3 {
		t.Errorf("ImpossibleTaskRate = %v, want 0.3", tm.AgentCollectives[0].RewardHacking.ImpossibleTaskRate)
	}
}

func TestFlowTypeCoordinationEnum(t *testing.T) {
	if FlowTypeCoordination != "coordination" {
		t.Errorf("FlowTypeCoordination = %q, want %q", FlowTypeCoordination, "coordination")
	}
	enum := FlowType("").JSONSchema().Enum
	found := false
	for _, v := range enum {
		if v == "coordination" {
			found = true
		}
	}
	if !found {
		t.Error("FlowType JSONSchema enum missing \"coordination\"")
	}
}

func TestAgenticCollectiveBuiltinPatterns(t *testing.T) {
	for _, id := range []string{"reward-hacking", "emergent-agent-coordination"} {
		p := GetAttackPattern(id)
		if p == nil {
			t.Fatalf("GetAttackPattern(%q) = nil, want pattern", id)
		}
		if p.ID != id {
			t.Errorf("pattern ID = %q, want %q", p.ID, id)
		}
		if p.Type == "" {
			t.Errorf("pattern %q has empty type", id)
		}
		if len(p.ASIIds) == 0 {
			t.Errorf("pattern %q should map to at least one ASI id", id)
		}
	}
}
