// Package ir provides the intermediate representation for threat models.
package ir

import (
	"strings"
	"time"
)

// KEVEntry represents an entry from CISA's Known Exploited Vulnerabilities (KEV) catalog.
// The KEV catalog contains vulnerabilities that have been actively exploited in the wild.
type KEVEntry struct {
	CVEID             string `json:"cveId"`                       // CVE identifier (e.g., "CVE-2024-1234")
	VendorProject     string `json:"vendorProject"`               // Vendor or project name
	Product           string `json:"product"`                     // Product name
	VulnerabilityName string `json:"vulnerabilityName"`           // Brief vulnerability name
	DateAdded         string `json:"dateAdded"`                   // Date added to KEV catalog (YYYY-MM-DD)
	ShortDescription  string `json:"shortDescription"`            // Brief vulnerability description
	RequiredAction    string `json:"requiredAction"`              // Required remediation action
	DueDate           string `json:"dueDate"`                     // Federal agency due date for remediation (YYYY-MM-DD)
	KnownRansomware   bool   `json:"knownRansomwareCampaignUse"`  // Used in ransomware campaigns
	Notes             string `json:"notes,omitempty"`             // Additional notes
}

// IsPastDue returns true if the due date has passed.
func (k *KEVEntry) IsPastDue() bool {
	if k.DueDate == "" {
		return false
	}
	dueDate, err := time.Parse("2006-01-02", k.DueDate)
	if err != nil {
		return false
	}
	return time.Now().After(dueDate)
}

// DaysUntilDue returns the number of days until the due date.
// Returns negative values if past due, 0 if due today.
func (k *KEVEntry) DaysUntilDue() int {
	if k.DueDate == "" {
		return 0
	}
	dueDate, err := time.Parse("2006-01-02", k.DueDate)
	if err != nil {
		return 0
	}
	return int(time.Until(dueDate).Hours() / 24)
}

// KEVCatalog provides lookup functionality for CISA KEV entries.
// This can be populated from the CISA KEV JSON feed or embedded data.
type KEVCatalog struct {
	Entries       map[string]KEVEntry `json:"entries"`                 // CVE ID -> KEV entry
	CatalogDate   string              `json:"catalogDate,omitempty"`   // Date of catalog snapshot
	CatalogSource string              `json:"catalogSource,omitempty"` // Source URL or identifier
	Count         int                 `json:"count,omitempty"`         // Total number of entries
}

// NewKEVCatalog creates a new empty KEV catalog.
func NewKEVCatalog() *KEVCatalog {
	return &KEVCatalog{
		Entries: make(map[string]KEVEntry),
	}
}

// GetKEVEntry returns the KEV entry for a given CVE ID, or nil if not found.
func (c *KEVCatalog) GetKEVEntry(cveID string) *KEVEntry {
	if c == nil || c.Entries == nil {
		return nil
	}
	// Normalize CVE ID format
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if entry, ok := c.Entries[cveID]; ok {
		return &entry
	}
	return nil
}

// IsInKEV returns true if the CVE is in the KEV catalog.
func (c *KEVCatalog) IsInKEV(cveID string) bool {
	return c.GetKEVEntry(cveID) != nil
}

// AddEntry adds a KEV entry to the catalog.
func (c *KEVCatalog) AddEntry(entry KEVEntry) {
	if c.Entries == nil {
		c.Entries = make(map[string]KEVEntry)
	}
	c.Entries[entry.CVEID] = entry
	c.Count = len(c.Entries)
}

// GetRansomwareVulnerabilities returns all KEV entries used in ransomware campaigns.
func (c *KEVCatalog) GetRansomwareVulnerabilities() []KEVEntry {
	var results []KEVEntry
	if c == nil || c.Entries == nil {
		return results
	}
	for _, entry := range c.Entries {
		if entry.KnownRansomware {
			results = append(results, entry)
		}
	}
	return results
}

// GetPastDueVulnerabilities returns all KEV entries that are past their due date.
func (c *KEVCatalog) GetPastDueVulnerabilities() []KEVEntry {
	var results []KEVEntry
	if c == nil || c.Entries == nil {
		return results
	}
	for _, entry := range c.Entries {
		if entry.IsPastDue() {
			results = append(results, entry)
		}
	}
	return results
}

// GetVulnerabilitiesByVendor returns all KEV entries for a specific vendor.
func (c *KEVCatalog) GetVulnerabilitiesByVendor(vendor string) []KEVEntry {
	var results []KEVEntry
	if c == nil || c.Entries == nil {
		return results
	}
	vendor = strings.ToLower(vendor)
	for _, entry := range c.Entries {
		if strings.ToLower(entry.VendorProject) == vendor {
			results = append(results, entry)
		}
	}
	return results
}

// KEVStatus represents the KEV status for a CVE.
type KEVStatus struct {
	InKEV           bool   `json:"inKev"`                     // Whether the CVE is in KEV
	KnownRansomware bool   `json:"knownRansomware,omitempty"` // Used in ransomware campaigns
	DateAdded       string `json:"dateAdded,omitempty"`       // Date added to KEV
	DueDate         string `json:"dueDate,omitempty"`         // Remediation due date
	IsPastDue       bool   `json:"isPastDue,omitempty"`       // Whether past due date
	RequiredAction  string `json:"requiredAction,omitempty"`  // Required action
}

// GetKEVStatus returns the KEV status for a CVE ID.
// This provides a summary suitable for inclusion in threat model reports.
func (c *KEVCatalog) GetKEVStatus(cveID string) *KEVStatus {
	entry := c.GetKEVEntry(cveID)
	if entry == nil {
		return &KEVStatus{InKEV: false}
	}
	return &KEVStatus{
		InKEV:           true,
		KnownRansomware: entry.KnownRansomware,
		DateAdded:       entry.DateAdded,
		DueDate:         entry.DueDate,
		IsPastDue:       entry.IsPastDue(),
		RequiredAction:  entry.RequiredAction,
	}
}

// Some commonly referenced KEV entries for testing and examples.
// In production, use the full CISA KEV catalog.
var sampleKEVEntries = []KEVEntry{
	{
		CVEID:             "CVE-2021-44228",
		VendorProject:     "Apache",
		Product:           "Log4j",
		VulnerabilityName: "Apache Log4j Remote Code Execution",
		DateAdded:         "2021-12-10",
		ShortDescription:  "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
		RequiredAction:    "Apply updates per vendor instructions.",
		DueDate:           "2021-12-24",
		KnownRansomware:   true,
	},
	{
		CVEID:             "CVE-2023-23397",
		VendorProject:     "Microsoft",
		Product:           "Outlook",
		VulnerabilityName: "Microsoft Outlook Elevation of Privilege Vulnerability",
		DateAdded:         "2023-03-14",
		ShortDescription:  "Microsoft Outlook contains an elevation of privilege vulnerability.",
		RequiredAction:    "Apply updates per vendor instructions.",
		DueDate:           "2023-04-04",
		KnownRansomware:   false,
	},
	{
		CVEID:             "CVE-2024-3400",
		VendorProject:     "Palo Alto Networks",
		Product:           "PAN-OS",
		VulnerabilityName: "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
		DateAdded:         "2024-04-12",
		ShortDescription:  "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability.",
		RequiredAction:    "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
		DueDate:           "2024-04-19",
		KnownRansomware:   false,
	},
}

// NewSampleKEVCatalog creates a KEV catalog with sample entries for testing.
func NewSampleKEVCatalog() *KEVCatalog {
	catalog := NewKEVCatalog()
	catalog.CatalogSource = "Sample data for testing"
	catalog.CatalogDate = time.Now().Format("2006-01-02")
	for _, entry := range sampleKEVEntries {
		catalog.AddEntry(entry)
	}
	return catalog
}
