package ir

import (
	"encoding/json"
	"testing"
)

func TestKEVEntryJSONRoundTrip(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2024-1234",
		VendorProject:     "TestVendor",
		Product:           "TestProduct",
		VulnerabilityName: "Test Vulnerability",
		DateAdded:         "2024-01-15",
		ShortDescription:  "A test vulnerability description",
		RequiredAction:    "Apply vendor patch",
		DueDate:           "2024-02-15",
		KnownRansomware:   true,
		Notes:             "Additional notes",
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal KEVEntry: %v", err)
	}

	var decoded KEVEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KEVEntry: %v", err)
	}

	if decoded.CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %s, want CVE-2024-1234", decoded.CVEID)
	}
	if decoded.VendorProject != "TestVendor" {
		t.Errorf("VendorProject = %s, want TestVendor", decoded.VendorProject)
	}
	if !decoded.KnownRansomware {
		t.Error("KnownRansomware should be true")
	}
}

func TestKEVEntryIsPastDue(t *testing.T) {
	tests := []struct {
		name       string
		dueDate    string
		wantPastDue bool
	}{
		{
			name:       "past due date",
			dueDate:    "2020-01-01",
			wantPastDue: true,
		},
		{
			name:       "future due date",
			dueDate:    "2099-12-31",
			wantPastDue: false,
		},
		{
			name:       "empty due date",
			dueDate:    "",
			wantPastDue: false,
		},
		{
			name:       "invalid due date",
			dueDate:    "not-a-date",
			wantPastDue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := KEVEntry{DueDate: tt.dueDate}
			if got := entry.IsPastDue(); got != tt.wantPastDue {
				t.Errorf("IsPastDue() = %v, want %v", got, tt.wantPastDue)
			}
		})
	}
}

func TestKEVEntryDaysUntilDue(t *testing.T) {
	// Test with past date (should be negative)
	pastEntry := KEVEntry{DueDate: "2020-01-01"}
	if pastEntry.DaysUntilDue() >= 0 {
		t.Error("DaysUntilDue() for past date should be negative")
	}

	// Test with future date (should be positive)
	futureEntry := KEVEntry{DueDate: "2099-12-31"}
	if futureEntry.DaysUntilDue() <= 0 {
		t.Error("DaysUntilDue() for future date should be positive")
	}

	// Test with empty date
	emptyEntry := KEVEntry{DueDate: ""}
	if emptyEntry.DaysUntilDue() != 0 {
		t.Errorf("DaysUntilDue() for empty date = %d, want 0", emptyEntry.DaysUntilDue())
	}
}

func TestKEVCatalogLookup(t *testing.T) {
	catalog := NewSampleKEVCatalog()

	// Test GetKEVEntry for existing CVE
	entry := catalog.GetKEVEntry("CVE-2021-44228")
	if entry == nil {
		t.Fatal("GetKEVEntry() returned nil for CVE-2021-44228")
	}
	if entry.VendorProject != "Apache" {
		t.Errorf("VendorProject = %s, want Apache", entry.VendorProject)
	}
	if entry.Product != "Log4j" {
		t.Errorf("Product = %s, want Log4j", entry.Product)
	}
	if !entry.KnownRansomware {
		t.Error("Log4j CVE should have KnownRansomware = true")
	}

	// Test GetKEVEntry for non-existing CVE
	entry = catalog.GetKEVEntry("CVE-9999-9999")
	if entry != nil {
		t.Error("GetKEVEntry() should return nil for non-existing CVE")
	}

	// Test IsInKEV
	if !catalog.IsInKEV("CVE-2021-44228") {
		t.Error("IsInKEV() should return true for CVE-2021-44228")
	}
	if catalog.IsInKEV("CVE-9999-9999") {
		t.Error("IsInKEV() should return false for non-existing CVE")
	}

	// Test case-insensitivity
	entry = catalog.GetKEVEntry("cve-2021-44228")
	if entry == nil {
		t.Error("GetKEVEntry() should be case-insensitive")
	}
}

func TestKEVCatalogFilters(t *testing.T) {
	catalog := NewSampleKEVCatalog()

	// Test GetRansomwareVulnerabilities
	ransomware := catalog.GetRansomwareVulnerabilities()
	if len(ransomware) == 0 {
		t.Error("GetRansomwareVulnerabilities() returned empty, expected at least Log4j")
	}
	foundLog4j := false
	for _, entry := range ransomware {
		if entry.CVEID == "CVE-2021-44228" {
			foundLog4j = true
			break
		}
	}
	if !foundLog4j {
		t.Error("GetRansomwareVulnerabilities() should include Log4j")
	}

	// Test GetVulnerabilitiesByVendor
	apache := catalog.GetVulnerabilitiesByVendor("Apache")
	if len(apache) == 0 {
		t.Error("GetVulnerabilitiesByVendor('Apache') returned empty")
	}

	// Test case-insensitivity for vendor
	apacheLower := catalog.GetVulnerabilitiesByVendor("apache")
	if len(apacheLower) != len(apache) {
		t.Error("GetVulnerabilitiesByVendor() should be case-insensitive")
	}

	// Test GetPastDueVulnerabilities (sample entries have past due dates)
	pastDue := catalog.GetPastDueVulnerabilities()
	if len(pastDue) == 0 {
		t.Error("GetPastDueVulnerabilities() returned empty, sample entries should be past due")
	}
}

func TestKEVCatalogNil(t *testing.T) {
	var catalog *KEVCatalog

	// Should not panic on nil catalog
	entry := catalog.GetKEVEntry("CVE-2021-44228")
	if entry != nil {
		t.Error("GetKEVEntry() on nil catalog should return nil")
	}

	if catalog.IsInKEV("CVE-2021-44228") {
		t.Error("IsInKEV() on nil catalog should return false")
	}

	ransomware := catalog.GetRansomwareVulnerabilities()
	if len(ransomware) != 0 {
		t.Error("GetRansomwareVulnerabilities() on nil catalog should return empty")
	}
}

func TestKEVStatus(t *testing.T) {
	catalog := NewSampleKEVCatalog()

	// Test status for CVE in KEV
	status := catalog.GetKEVStatus("CVE-2021-44228")
	if !status.InKEV {
		t.Error("InKEV should be true for CVE-2021-44228")
	}
	if !status.KnownRansomware {
		t.Error("KnownRansomware should be true for Log4j")
	}
	if !status.IsPastDue {
		t.Error("IsPastDue should be true for Log4j (2021 due date)")
	}
	if status.DateAdded == "" {
		t.Error("DateAdded should not be empty")
	}

	// Test status for CVE not in KEV
	status = catalog.GetKEVStatus("CVE-9999-9999")
	if status.InKEV {
		t.Error("InKEV should be false for non-existing CVE")
	}
}

func TestKEVCatalogAddEntry(t *testing.T) {
	catalog := NewKEVCatalog()
	if catalog.Count != 0 {
		t.Errorf("New catalog Count = %d, want 0", catalog.Count)
	}

	entry := KEVEntry{
		CVEID:         "CVE-2024-9999",
		VendorProject: "Test",
		Product:       "Test Product",
	}
	catalog.AddEntry(entry)

	if catalog.Count != 1 {
		t.Errorf("Count after add = %d, want 1", catalog.Count)
	}

	retrieved := catalog.GetKEVEntry("CVE-2024-9999")
	if retrieved == nil {
		t.Error("Failed to retrieve added entry")
	}
}

func TestKEVCatalogJSONRoundTrip(t *testing.T) {
	catalog := NewSampleKEVCatalog()

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal KEVCatalog: %v", err)
	}

	var decoded KEVCatalog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KEVCatalog: %v", err)
	}

	if len(decoded.Entries) != len(catalog.Entries) {
		t.Errorf("Entries count = %d, want %d", len(decoded.Entries), len(catalog.Entries))
	}
	if decoded.CatalogSource != catalog.CatalogSource {
		t.Errorf("CatalogSource = %s, want %s", decoded.CatalogSource, catalog.CatalogSource)
	}
}
