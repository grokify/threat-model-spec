package killchain

import "testing"

func TestMITRETacticString(t *testing.T) {
	tests := []struct {
		tactic MITRETactic
		want   string
	}{
		{InitialAccess, "Initial Access"},
		{Execution, "Execution"},
		{Persistence, "Persistence"},
		{PrivilegeEscalation, "Privilege Escalation"},
		{DefenseEvasion, "Defense Evasion"},
		{CredentialAccess, "Credential Access"},
		{Discovery, "Discovery"},
		{LateralMovement, "Lateral Movement"},
		{Collection, "Collection"},
		{CommandAndControl, "Command and Control"},
		{Exfiltration, "Exfiltration"},
		{Impact, "Impact"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.tactic.String(); got != tt.want {
				t.Errorf("MITRETactic.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMITRETacticURL(t *testing.T) {
	tactic := InitialAccess
	want := "https://attack.mitre.org/tactics/TA0001/"
	if got := tactic.URL(); got != want {
		t.Errorf("MITRETactic.URL() = %v, want %v", got, want)
	}
}

func TestTechniqueURL(t *testing.T) {
	technique := Technique{
		ID:     "T1199",
		Name:   "Trusted Relationship",
		Tactic: InitialAccess,
	}
	want := "https://attack.mitre.org/techniques/T1199/"
	if got := technique.URL(); got != want {
		t.Errorf("Technique.URL() = %v, want %v", got, want)
	}
}

func TestTechniqueLabel(t *testing.T) {
	technique := Technique{
		ID:     "T1199",
		Name:   "Trusted Relationship",
		Tactic: InitialAccess,
	}
	want := "TA0001 Initial Access\nT1199 Trusted Relationship"
	if got := technique.Label(); got != want {
		t.Errorf("Technique.Label() = %v, want %v", got, want)
	}
}

func TestAllMITRETactics(t *testing.T) {
	tactics := AllMITRETactics()
	if len(tactics) != 14 {
		t.Errorf("AllMITRETactics() returned %d tactics, want 14", len(tactics))
	}
}

func TestLockheedPhaseString(t *testing.T) {
	tests := []struct {
		phase LockheedPhase
		want  string
	}{
		{Recon, "Reconnaissance"},
		{Weaponization, "Weaponization"},
		{Delivery, "Delivery"},
		{Exploitation, "Exploitation"},
		{Installation, "Installation"},
		{CommandControl, "Command & Control"},
		{ActionsOnObjectives, "Actions on Objectives"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.phase.String(); got != tt.want {
				t.Errorf("LockheedPhase.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLockheedPhaseNumber(t *testing.T) {
	tests := []struct {
		phase LockheedPhase
		want  int
	}{
		{Recon, 1},
		{Weaponization, 2},
		{Delivery, 3},
		{Exploitation, 4},
		{Installation, 5},
		{CommandControl, 6},
		{ActionsOnObjectives, 7},
	}

	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			if got := tt.phase.Number(); got != tt.want {
				t.Errorf("LockheedPhase.Number() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllLockheedPhases(t *testing.T) {
	phases := AllLockheedPhases()
	if len(phases) != 7 {
		t.Errorf("AllLockheedPhases() returned %d phases, want 7", len(phases))
	}

	// Verify order
	for i, phase := range phases {
		if phase.Number() != i+1 {
			t.Errorf("AllLockheedPhases()[%d].Number() = %v, want %v", i, phase.Number(), i+1)
		}
	}
}

func TestKillChainStepLabel(t *testing.T) {
	step := KillChainStep{
		Phase:       Delivery,
		Description: "Victim visits malicious site",
	}
	want := "Deliver: Victim visits malicious site"
	if got := step.Label(); got != want {
		t.Errorf("KillChainStep.Label() = %v, want %v", got, want)
	}
}
