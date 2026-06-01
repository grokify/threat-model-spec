package ir

import (
	"testing"
)

func TestBuiltinAttackPatterns(t *testing.T) {
	patterns := BuiltinAttackPatterns()

	if len(patterns) == 0 {
		t.Error("Expected built-in attack patterns to be non-empty")
	}

	// Check that each pattern has required fields
	for _, p := range patterns {
		if p.ID == "" {
			t.Error("Pattern ID should not be empty")
		}
		if p.Name == "" {
			t.Errorf("Pattern %s has empty name", p.ID)
		}
		if p.Type == "" {
			t.Errorf("Pattern %s has empty type", p.ID)
		}
	}
}

func TestCSWSHPattern(t *testing.T) {
	pattern := CSWSHPattern()

	if pattern.ID != "pattern-cswsh" {
		t.Errorf("Expected ID 'pattern-cswsh', got %s", pattern.ID)
	}

	if pattern.Type != AttackPatternCSWSH {
		t.Errorf("Expected type CSWSH, got %s", pattern.Type)
	}

	// Should have CWE-346 (Origin Validation Error)
	hasCWE346 := false
	for _, cwe := range pattern.CWEIDs {
		if cwe == "CWE-346" {
			hasCWE346 = true
			break
		}
	}
	if !hasCWE346 {
		t.Error("CSWSH pattern should include CWE-346")
	}

	// Should have attack steps
	if len(pattern.AttackSteps) == 0 {
		t.Error("CSWSH pattern should have attack steps")
	}

	// Should have vulnerable patterns
	if len(pattern.VulnerablePatterns) == 0 {
		t.Error("CSWSH pattern should have vulnerable code patterns")
	}

	// Should have secure patterns
	if len(pattern.SecurePatterns) == 0 {
		t.Error("CSWSH pattern should have secure code patterns")
	}

	// Should have detection patterns
	if len(pattern.DetectionPatterns) == 0 {
		t.Error("CSWSH pattern should have detection patterns")
	}
}

func TestTokenExfiltrationPattern(t *testing.T) {
	pattern := TokenExfiltrationPattern()

	if pattern.ID != "pattern-token-exfil" {
		t.Errorf("Expected ID 'pattern-token-exfil', got %s", pattern.ID)
	}

	if pattern.Type != AttackPatternTokenExfiltration {
		t.Errorf("Expected type TokenExfiltration, got %s", pattern.Type)
	}

	// Should have T1528 (Steal Application Access Token)
	hasT1528 := false
	for _, tech := range pattern.MITRETechniques {
		if tech == "T1528" {
			hasT1528 = true
			break
		}
	}
	if !hasT1528 {
		t.Error("Token exfiltration pattern should include T1528")
	}
}

func TestSandboxEscapePattern(t *testing.T) {
	pattern := SandboxEscapePattern()

	if pattern.Type != AttackPatternSandboxEscape {
		t.Errorf("Expected type SandboxEscape, got %s", pattern.Type)
	}

	// Should have T1611 (Escape to Host)
	hasT1611 := false
	for _, tech := range pattern.MITRETechniques {
		if tech == "T1611" {
			hasT1611 = true
			break
		}
	}
	if !hasT1611 {
		t.Error("Sandbox escape pattern should include T1611")
	}
}

func TestAgentToolAbusePattern(t *testing.T) {
	pattern := AgentToolAbusePattern()

	if pattern.Type != AttackPatternToolAbuse {
		t.Errorf("Expected type ToolAbuse, got %s", pattern.Type)
	}

	// Should have ASI05:2026 (Unexpected Code Execution)
	hasASI05 := false
	for _, asi := range pattern.ASIIds {
		if asi == "ASI05:2026" {
			hasASI05 = true
			break
		}
	}
	if !hasASI05 {
		t.Error("Agent tool abuse pattern should include ASI05:2026")
	}
}

func TestGetAttackPattern(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"pattern-cswsh", true},
		{"pattern-token-exfil", true},
		{"pattern-sandbox-escape", true},
		{"non-existent", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			pattern := GetAttackPattern(tt.id)
			if tt.expected && pattern == nil {
				t.Errorf("Expected to find pattern %s", tt.id)
			}
			if !tt.expected && pattern != nil {
				t.Errorf("Did not expect to find pattern %s", tt.id)
			}
		})
	}
}

func TestGetAttackPatternsByType(t *testing.T) {
	patterns := GetAttackPatternsByType(AttackPatternCSWSH)

	if len(patterns) == 0 {
		t.Error("Expected at least one CSWSH pattern")
	}

	for _, p := range patterns {
		if p.Type != AttackPatternCSWSH {
			t.Errorf("Expected all patterns to be CSWSH type, got %s", p.Type)
		}
	}
}

func TestAttackPatternType_JSONSchema(t *testing.T) {
	schema := AttackPatternCSWSH.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("Expected 10 enum values, got %d", len(schema.Enum))
	}
}
