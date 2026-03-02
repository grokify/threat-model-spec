package stride

import "testing"

func TestThreatTypeString(t *testing.T) {
	tests := []struct {
		threatType ThreatType
		want       string
	}{
		{Spoofing, "Spoofing"},
		{Tampering, "Tampering"},
		{Repudiation, "Repudiation"},
		{InformationDisclosure, "Information Disclosure"},
		{DenialOfService, "Denial of Service"},
		{ElevationOfPrivilege, "Elevation of Privilege"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.threatType.String(); got != tt.want {
				t.Errorf("ThreatType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestThreatTypeCode(t *testing.T) {
	tests := []struct {
		threatType ThreatType
		want       string
	}{
		{Spoofing, "S"},
		{Tampering, "T"},
		{Repudiation, "R"},
		{InformationDisclosure, "I"},
		{DenialOfService, "D"},
		{ElevationOfPrivilege, "E"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.threatType.Code(); got != tt.want {
				t.Errorf("ThreatType.Code() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestThreatTypeD2Class(t *testing.T) {
	tests := []struct {
		threatType ThreatType
		want       string
	}{
		{Spoofing, "threat-spoofing"},
		{Tampering, "threat-tampering"},
		{Repudiation, "threat-repudiation"},
		{InformationDisclosure, "threat-info-disclosure"},
		{DenialOfService, "threat-dos"},
		{ElevationOfPrivilege, "threat-elevation"},
	}

	for _, tt := range tests {
		t.Run(string(tt.threatType), func(t *testing.T) {
			if got := tt.threatType.D2Class(); got != tt.want {
				t.Errorf("ThreatType.D2Class() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllThreatTypes(t *testing.T) {
	types := AllThreatTypes()
	if len(types) != 6 {
		t.Errorf("AllThreatTypes() returned %d types, want 6", len(types))
	}

	// Verify STRIDE order
	expected := []ThreatType{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}

	for i, tt := range expected {
		if types[i] != tt {
			t.Errorf("AllThreatTypes()[%d] = %v, want %v", i, types[i], tt)
		}
	}
}

func TestThreatLabel(t *testing.T) {
	threat := Threat{
		Type:  Spoofing,
		Title: "Localhost spoofing",
	}

	want := "S - Localhost spoofing"
	if got := threat.Label(); got != want {
		t.Errorf("Threat.Label() = %v, want %v", got, want)
	}
}

func TestThreatLabelNoTitle(t *testing.T) {
	threat := Threat{
		Type: ElevationOfPrivilege,
	}

	want := "E - Elevation of Privilege"
	if got := threat.Label(); got != want {
		t.Errorf("Threat.Label() = %v, want %v", got, want)
	}
}

func TestThreatD2ID(t *testing.T) {
	threat := Threat{
		Type:      Spoofing,
		ElementID: "gateway",
	}

	want := "threat-S-gateway"
	if got := threat.D2ID(); got != want {
		t.Errorf("Threat.D2ID() = %v, want %v", got, want)
	}
}
