package ir

import (
	"encoding/json"
	"testing"
)

func TestSBOMReferenceJSONRoundTrip(t *testing.T) {
	sbom := SBOMReference{
		Format:       SBOMFormatCycloneDX,
		Version:      "1.5",
		URI:          "https://example.com/sbom.json",
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Components: []ComponentReference{
			{
				ID:      "pkg:npm/lodash@4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
				Name:    "lodash",
				Version: "4.17.21",
				License: "MIT",
				VulnerabilityIDs: []string{"CVE-2021-23337", "CVE-2020-8203"},
			},
		},
	}

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal SBOMReference: %v", err)
	}

	var decoded SBOMReference
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SBOMReference: %v", err)
	}

	if decoded.Format != SBOMFormatCycloneDX {
		t.Errorf("Format = %s, want cyclonedx", decoded.Format)
	}
	if decoded.Version != "1.5" {
		t.Errorf("Version = %s, want 1.5", decoded.Version)
	}
	if len(decoded.Components) != 1 {
		t.Fatalf("Components length = %d, want 1", len(decoded.Components))
	}
	if decoded.Components[0].Name != "lodash" {
		t.Errorf("Components[0].Name = %s, want lodash", decoded.Components[0].Name)
	}
	if len(decoded.Components[0].VulnerabilityIDs) != 2 {
		t.Errorf("VulnerabilityIDs length = %d, want 2", len(decoded.Components[0].VulnerabilityIDs))
	}
}

func TestComponentReferenceJSONRoundTrip(t *testing.T) {
	comp := ComponentReference{
		ID:       "component-1",
		PURL:     "pkg:golang/github.com/example/lib@v1.2.3",
		CPE:      "cpe:2.3:a:example:lib:1.2.3:*:*:*:*:*:*:*",
		Name:     "example-lib",
		Version:  "1.2.3",
		Supplier: "Example Inc",
		License:  "Apache-2.0",
		VulnerabilityIDs: []string{"CVE-2024-12345"},
	}

	data, err := json.MarshalIndent(comp, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal ComponentReference: %v", err)
	}

	var decoded ComponentReference
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ComponentReference: %v", err)
	}

	if decoded.PURL != comp.PURL {
		t.Errorf("PURL = %s, want %s", decoded.PURL, comp.PURL)
	}
	if decoded.CPE != comp.CPE {
		t.Errorf("CPE = %s, want %s", decoded.CPE, comp.CPE)
	}
	if decoded.License != "Apache-2.0" {
		t.Errorf("License = %s, want Apache-2.0", decoded.License)
	}
}

func TestDependencyRiskJSONRoundTrip(t *testing.T) {
	risk := DependencyRisk{
		ComponentRef: ComponentReference{
			Name:    "vulnerable-lib",
			Version: "1.0.0",
			PURL:    "pkg:npm/vulnerable-lib@1.0.0",
		},
		RiskLevel:          RiskLevelHigh,
		VulnerabilityCount: 5,
		CriticalCount:      1,
		HighCount:          2,
		OutdatedBy:         3,
		Deprecated:         false,
		Unmaintained:       true,
		DirectDependency:   true,
		Notes:              "Component has not been updated in 2 years",
	}

	data, err := json.MarshalIndent(risk, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal DependencyRisk: %v", err)
	}

	var decoded DependencyRisk
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DependencyRisk: %v", err)
	}

	if decoded.RiskLevel != RiskLevelHigh {
		t.Errorf("RiskLevel = %s, want high", decoded.RiskLevel)
	}
	if decoded.VulnerabilityCount != 5 {
		t.Errorf("VulnerabilityCount = %d, want 5", decoded.VulnerabilityCount)
	}
	if decoded.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", decoded.CriticalCount)
	}
	if !decoded.Unmaintained {
		t.Error("Unmaintained = false, want true")
	}
	if !decoded.DirectDependency {
		t.Error("DirectDependency = false, want true")
	}
}

func TestCalculateDependencyRiskLevel(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount int
		highCount     int
		mediumCount   int
		deprecated    bool
		unmaintained  bool
		want          RiskLevel
	}{
		{
			name:          "critical vulnerabilities",
			criticalCount: 1,
			highCount:     0,
			mediumCount:   0,
			deprecated:    false,
			unmaintained:  false,
			want:          RiskLevelCritical,
		},
		{
			name:          "deprecated with high vulnerabilities",
			criticalCount: 0,
			highCount:     1,
			mediumCount:   0,
			deprecated:    true,
			unmaintained:  false,
			want:          RiskLevelCritical,
		},
		{
			name:          "high vulnerabilities only",
			criticalCount: 0,
			highCount:     2,
			mediumCount:   0,
			deprecated:    false,
			unmaintained:  false,
			want:          RiskLevelHigh,
		},
		{
			name:          "unmaintained with medium vulnerabilities",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   3,
			deprecated:    false,
			unmaintained:  true,
			want:          RiskLevelHigh,
		},
		{
			name:          "medium vulnerabilities only",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   2,
			deprecated:    false,
			unmaintained:  false,
			want:          RiskLevelMedium,
		},
		{
			name:          "deprecated only",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   0,
			deprecated:    true,
			unmaintained:  false,
			want:          RiskLevelMedium,
		},
		{
			name:          "unmaintained only",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   0,
			deprecated:    false,
			unmaintained:  true,
			want:          RiskLevelMedium,
		},
		{
			name:          "no issues",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   0,
			deprecated:    false,
			unmaintained:  false,
			want:          RiskLevelLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateDependencyRiskLevel(tt.criticalCount, tt.highCount, tt.mediumCount, tt.deprecated, tt.unmaintained)
			if got != tt.want {
				t.Errorf("CalculateDependencyRiskLevel() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSBOMFormats(t *testing.T) {
	// Test format constants
	if SBOMFormatCycloneDX != "cyclonedx" {
		t.Errorf("SBOMFormatCycloneDX = %s, want cyclonedx", SBOMFormatCycloneDX)
	}
	if SBOMFormatSPDX != "spdx" {
		t.Errorf("SBOMFormatSPDX = %s, want spdx", SBOMFormatSPDX)
	}

	// Test JSON serialization of formats
	testCases := []struct {
		format SBOMFormat
		want   string
	}{
		{SBOMFormatCycloneDX, `"cyclonedx"`},
		{SBOMFormatSPDX, `"spdx"`},
	}

	for _, tc := range testCases {
		data, err := json.Marshal(tc.format)
		if err != nil {
			t.Errorf("Failed to marshal %s: %v", tc.format, err)
			continue
		}
		if string(data) != tc.want {
			t.Errorf("Marshal(%s) = %s, want %s", tc.format, string(data), tc.want)
		}
	}
}
