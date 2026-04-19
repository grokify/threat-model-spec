package ir

import "testing"

func TestScenarioType_Values(t *testing.T) {
	types := []ScenarioType{
		ScenarioTypeExternalAttack,
		ScenarioTypeInsiderThreat,
		ScenarioTypeSupplyChain,
		ScenarioTypeDataBreach,
		ScenarioTypePrivacyViolation,
		ScenarioTypeDenialOfService,
		ScenarioTypeEscalation,
	}

	expected := []string{
		"external-attack",
		"insider-threat",
		"supply-chain",
		"data-breach",
		"privacy-violation",
		"denial-of-service",
		"escalation",
	}

	for i, st := range types {
		if string(st) != expected[i] {
			t.Errorf("ScenarioType %d = %s, want %s", i, st, expected[i])
		}
	}
}

func TestScenario_Fields(t *testing.T) {
	scenario := Scenario{
		ID:            "scenario-1",
		Title:         "External Attacker Compromises API",
		Description:   "An external attacker exploits an API vulnerability to access user data",
		Type:          ScenarioTypeExternalAttack,
		ThreatActorID: "actor-external",
		Preconditions: []string{
			"Attacker has network access to public API",
			"API has authentication bypass vulnerability",
		},
		AttackPath: []string{
			"Reconnaissance of public API",
			"Identify auth bypass",
			"Exploit vulnerability",
			"Access user database",
		},
		TargetAssetIDs: []string{"asset-userdb"},
		Risk: &RiskAssessment{
			Likelihood: 4,
			Impact:     5,
		},
		Outcome:        "Unauthorized access to user PII",
		BusinessImpact: "Regulatory fines, reputation damage",
		MitigationIDs:  []string{"mit-api-auth"},
	}

	scenario.Risk.Calculate()

	if scenario.ID != "scenario-1" {
		t.Errorf("ID = %s, want scenario-1", scenario.ID)
	}
	if scenario.Type != ScenarioTypeExternalAttack {
		t.Errorf("Type = %s, want external-attack", scenario.Type)
	}
	if len(scenario.Preconditions) != 2 {
		t.Errorf("Preconditions length = %d, want 2", len(scenario.Preconditions))
	}
	if scenario.Risk.Score != 20 {
		t.Errorf("Risk.Score = %d, want 20", scenario.Risk.Score)
	}
	if scenario.Risk.Level != RiskLevelCritical {
		t.Errorf("Risk.Level = %s, want critical", scenario.Risk.Level)
	}
}
