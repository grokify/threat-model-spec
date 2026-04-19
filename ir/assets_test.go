package ir

import "testing"

func TestSensitivityLevel_Values(t *testing.T) {
	levels := []SensitivityLevel{
		SensitivityPublic,
		SensitivityInternal,
		SensitivityConfidential,
		SensitivityRestricted,
		SensitivitySecret,
	}

	expected := []string{"public", "internal", "confidential", "restricted", "secret"}

	for i, level := range levels {
		if string(level) != expected[i] {
			t.Errorf("SensitivityLevel %d = %s, want %s", i, level, expected[i])
		}
	}
}

func TestAssetType_Values(t *testing.T) {
	types := []AssetType{
		AssetTypeData,
		AssetTypeService,
		AssetTypeInfrastructure,
		AssetTypeCredential,
		AssetTypeIdentity,
		AssetTypeIntellectualProperty,
	}

	expected := []string{"data", "service", "infrastructure", "credential", "identity", "intellectual-property"}

	for i, at := range types {
		if string(at) != expected[i] {
			t.Errorf("AssetType %d = %s, want %s", i, at, expected[i])
		}
	}
}

func TestAsset_Fields(t *testing.T) {
	asset := Asset{
		ID:             "asset-1",
		Name:           "User Database",
		Description:    "PostgreSQL database containing user PII",
		Type:           AssetTypeData,
		Classification: SensitivityRestricted,
		Owner:          "data-team",
		ElementIDs:     []string{"db-users"},
		DataTypes:      []string{"PII", "credentials"},
		ComplianceFrameworks: []string{"GDPR", "SOC2"},
		Value:          "High business value - core user data",
	}

	if asset.ID != "asset-1" {
		t.Errorf("ID = %s, want asset-1", asset.ID)
	}
	if asset.Classification != SensitivityRestricted {
		t.Errorf("Classification = %s, want restricted", asset.Classification)
	}
	if len(asset.DataTypes) != 2 {
		t.Errorf("DataTypes length = %d, want 2", len(asset.DataTypes))
	}
}
