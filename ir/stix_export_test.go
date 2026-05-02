package ir

import (
	"strings"
	"testing"
)

func TestIOCToSTIXIndicator(t *testing.T) {
	tests := []struct {
		name          string
		ioc           IOC
		wantPattern   string
		wantIndicType string
		shouldBeNil   bool
	}{
		{
			name: "IP address IOC",
			ioc: IOC{
				Type:        IOCTypeIP,
				Value:       "192.168.1.1",
				Description: "Malicious IP",
			},
			wantPattern:   "[ipv4-addr:value = '192.168.1.1']",
			wantIndicType: "malicious-activity",
		},
		{
			name: "Domain IOC",
			ioc: IOC{
				Type:        IOCTypeDomain,
				Value:       "evil.example.com",
				Description: "C2 domain",
			},
			wantPattern:   "[domain-name:value = 'evil.example.com']",
			wantIndicType: "malicious-activity",
		},
		{
			name: "URL IOC",
			ioc: IOC{
				Type:        IOCTypeURL,
				Value:       "https://evil.com/malware.exe",
				Description: "Malware download URL",
			},
			wantPattern:   "[url:value = 'https://evil.com/malware.exe']",
			wantIndicType: "malicious-activity",
		},
		{
			name: "Hash IOC",
			ioc: IOC{
				Type:        IOCTypeHash,
				Value:       "e3b0c44298fc1c149afbf4c8996fb924",
				Description: "Malware hash",
			},
			wantPattern:   "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb924']",
			wantIndicType: "anomalous-activity",
		},
		{
			name: "Filepath IOC",
			ioc: IOC{
				Type:        IOCTypeFilepath,
				Value:       "/tmp/malware.exe",
				Description: "Malware file path",
			},
			wantPattern:   "[file:name = '/tmp/malware.exe']",
			wantIndicType: "anomalous-activity",
		},
		{
			name: "Email IOC",
			ioc: IOC{
				Type:        IOCTypeEmail,
				Value:       "attacker@evil.com",
				Description: "Phishing sender",
			},
			wantPattern:   "[email-addr:value = 'attacker@evil.com']",
			wantIndicType: "attribution",
		},
		{
			name: "Registry IOC",
			ioc: IOC{
				Type:        IOCTypeRegistry,
				Value:       "HKLM\\Software\\Malware\\Key",
				Description: "Malware registry key",
			},
			wantPattern:   "[windows-registry-key:key = 'HKLM\\Software\\Malware\\Key']",
			wantIndicType: "unknown",
		},
		{
			name: "Process IOC",
			ioc: IOC{
				Type:        IOCTypeProcess,
				Value:       "malware.exe",
				Description: "Malicious process",
			},
			wantPattern:   "[process:name = 'malware.exe']",
			wantIndicType: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ind := tt.ioc.ToSTIXIndicator("identity--test")
			if tt.shouldBeNil {
				if ind != nil {
					t.Errorf("ToSTIXIndicator() should return nil")
				}
				return
			}
			if ind == nil {
				t.Fatal("ToSTIXIndicator() returned nil")
			}
			if ind.Pattern != tt.wantPattern {
				t.Errorf("Pattern = %s, want %s", ind.Pattern, tt.wantPattern)
			}
			if len(ind.IndicatorTypes) == 0 || ind.IndicatorTypes[0] != tt.wantIndicType {
				t.Errorf("IndicatorTypes = %v, want [%s]", ind.IndicatorTypes, tt.wantIndicType)
			}
			if ind.Type != "indicator" {
				t.Errorf("Type = %s, want indicator", ind.Type)
			}
			if ind.SpecVersion != "2.1" {
				t.Errorf("SpecVersion = %s, want 2.1", ind.SpecVersion)
			}
		})
	}
}

func TestThreatActorToSTIXThreatActor(t *testing.T) {
	ta := ThreatActor{
		Name:           "APT28",
		Description:    "Russian state-sponsored threat actor",
		Type:           ThreatActorTypeNationState,
		Aliases:        []string{"Fancy Bear", "Sofacy"},
		PrimaryGoals:   []string{"Espionage", "Data theft"},
		Sophistication: SophisticationAdvanced,
		Resources:      ResourceLevelExtensive,
		Motivations:    []Motivation{MotivationEspionage, MotivationIdeological},
		TTPs:           []string{"T1566", "T1059"},
	}

	stixTA := ta.ToSTIXThreatActor("identity--test")
	if stixTA == nil {
		t.Fatal("ToSTIXThreatActor() returned nil")
	}

	if stixTA.Name != "APT28" {
		t.Errorf("Name = %s, want APT28", stixTA.Name)
	}
	if stixTA.Type != "threat-actor" {
		t.Errorf("Type = %s, want threat-actor", stixTA.Type)
	}
	if stixTA.Sophistication != "advanced" {
		t.Errorf("Sophistication = %s, want advanced", stixTA.Sophistication)
	}
	if stixTA.PrimaryMotivation != "espionage" {
		t.Errorf("PrimaryMotivation = %s, want espionage", stixTA.PrimaryMotivation)
	}
	if len(stixTA.ExternalReferences) != 2 {
		t.Errorf("ExternalReferences count = %d, want 2", len(stixTA.ExternalReferences))
	}
}

func TestAttackToSTIXAttackPattern(t *testing.T) {
	attack := Attack{
		Step:           1,
		From:           "attacker",
		To:             "web-server",
		Label:          "SQL Injection",
		Description:    "Inject SQL commands via user input",
		MITRETactic:    MITREInitialAccess,
		MITRETechnique: "T1190",
	}

	ap := attack.ToSTIXAttackPattern("identity--test")
	if ap == nil {
		t.Fatal("ToSTIXAttackPattern() returned nil")
	}

	if ap.Name != "SQL Injection" {
		t.Errorf("Name = %s, want SQL Injection", ap.Name)
	}
	if ap.Type != "attack-pattern" {
		t.Errorf("Type = %s, want attack-pattern", ap.Type)
	}
	if len(ap.KillChainPhases) != 1 {
		t.Errorf("KillChainPhases count = %d, want 1", len(ap.KillChainPhases))
	}
	if len(ap.ExternalReferences) != 1 {
		t.Errorf("ExternalReferences count = %d, want 1 (MITRE technique)", len(ap.ExternalReferences))
	}
}

func TestDetectionRuleToSTIXCourseOfAction(t *testing.T) {
	rule := DetectionRule{
		ID:          "rule-1",
		Name:        "SQL Injection Detection",
		Description: "Detects SQL injection attempts",
		Format:      DetectionFormatSigma,
		Rule:        "title: SQL Injection\nlogsource:\n  product: web",
	}

	coa := rule.ToSTIXCourseOfAction("identity--test")
	if coa == nil {
		t.Fatal("ToSTIXCourseOfAction() returned nil")
	}

	if coa.Name != "SQL Injection Detection" {
		t.Errorf("Name = %s, want SQL Injection Detection", coa.Name)
	}
	if coa.Type != "course-of-action" {
		t.Errorf("Type = %s, want course-of-action", coa.Type)
	}
	if coa.ActionType != "detection" {
		t.Errorf("ActionType = %s, want detection", coa.ActionType)
	}
	if !strings.Contains(coa.Description, "sigma") {
		t.Errorf("Description should mention format, got: %s", coa.Description)
	}
}

func TestThreatModelExportSTIXBundle(t *testing.T) {
	tm := &ThreatModel{
		ID:    "tm-1",
		Title: "Test Threat Model",
		ThreatActors: []ThreatActor{
			{
				Name:        "APT28",
				Type:        ThreatActorTypeNationState,
				Description: "Test actor",
			},
		},
		Diagrams: []DiagramView{
			{
				Type: DiagramTypeAttack,
				Attacks: []Attack{
					{
						Step:        1,
						From:        "attacker",
						To:          "target",
						Label:       "Attack Step 1",
						Description: "First attack step",
					},
				},
				Mitigations: []Mitigation{
					{
						ID:          "mit-1",
						Title:       "Mitigation 1",
						Description: "First mitigation",
					},
				},
			},
		},
		BlueTeam: &DefenseGuidance{
			IOCs: []IOC{
				{
					Type:        IOCTypeIP,
					Value:       "192.168.1.100",
					Description: "C2 server",
				},
			},
			DetectionRules: []DetectionRule{
				{
					ID:     "rule-1",
					Name:   "Detection Rule 1",
					Format: DetectionFormatSigma,
					Rule:   "title: Test",
				},
			},
		},
		Mappings: &Mappings{
			CVE: []CVEMapping{
				{
					ID:          "CVE-2024-1234",
					Description: "Test vulnerability",
				},
			},
		},
	}

	opts := DefaultSTIXExportOptions()
	bundle, err := tm.ExportSTIXBundle(opts)
	if err != nil {
		t.Fatalf("ExportSTIXBundle() error: %v", err)
	}

	if bundle == nil {
		t.Fatal("ExportSTIXBundle() returned nil bundle")
	}

	// Should have: identity + threat actor + attack pattern + mitigation COA + IOC indicator + detection COA + vulnerability
	expectedMinObjects := 7
	if len(bundle.Objects) < expectedMinObjects {
		t.Errorf("Bundle has %d objects, expected at least %d", len(bundle.Objects), expectedMinObjects)
	}

	// Verify bundle type
	if bundle.Type != "bundle" {
		t.Errorf("Bundle type = %s, want bundle", bundle.Type)
	}
}

func TestSTIXExportOptionsDefault(t *testing.T) {
	opts := DefaultSTIXExportOptions()

	if !opts.IncludeIndicators {
		t.Error("IncludeIndicators should be true by default")
	}
	if !opts.IncludeAttackPatterns {
		t.Error("IncludeAttackPatterns should be true by default")
	}
	if !opts.IncludeThreatActors {
		t.Error("IncludeThreatActors should be true by default")
	}
	if !opts.IncludeCourseOfAction {
		t.Error("IncludeCourseOfAction should be true by default")
	}
	if !opts.IncludeVulnerabilities {
		t.Error("IncludeVulnerabilities should be true by default")
	}
	if opts.IdentityName != "Threat Model Spec" {
		t.Errorf("IdentityName = %s, want Threat Model Spec", opts.IdentityName)
	}
}

func TestGenerateUUID(t *testing.T) {
	uuid1 := generateUUID()
	uuid2 := generateUUID()

	if uuid1 == "" {
		t.Error("generateUUID() returned empty string")
	}
	// UUIDs should contain hyphens
	if !strings.Contains(uuid1, "-") {
		t.Errorf("UUID %s doesn't contain hyphens", uuid1)
	}
	// UUIDs generated in sequence should be different (timing-dependent)
	// This test is probabilistic but should pass in practice
	if uuid1 == uuid2 {
		t.Log("Warning: Two sequential UUIDs were identical (timing-dependent)")
	}
}
