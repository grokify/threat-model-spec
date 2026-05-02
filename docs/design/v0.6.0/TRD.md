# Technical Requirements Document: v0.6.0 - Comprehensive Security Enhancement

> **Version:** 0.6.0
> **Status:** In Progress
> **Date:** 2026-04-28

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           threat-model-spec v0.6.0                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Section A: OWASP ASI Support                                                │
│  ├── OWASPCategoryAgentic          ──────► ASI 2026 mapping                 │
│  ├── ASIIds []string (Attack)      ──────► Per-step ASI IDs                 │
│  └── OWASPReference data           ──────► 40 entries (API, LLM, Web, ASI)  │
│                                                                              │
│  Section B: Role-Based Security Data                                         │
│  ├── RedTeam      *ExploitationGuidance  ──────► Offensive Testing          │
│  ├── BlueTeam     *DefenseGuidance       ──────► SIEM/EDR/Hunting           │
│  ├── Remediation  *RemediationGuidance   ──────► Code Fixes                 │
│  ├── Playbooks    []IncidentPlaybook     ──────► IR Response                │
│  └── TestSuites   []TestSuiteReference   ──────► app-test-spec              │
│                                                                              │
│  Section C: Risk Quantification                                              │
│  ├── FAIRAssessment                ──────► Quantified risk                  │
│  ├── BusinessImpact                ──────► Revenue/customer impact          │
│  └── EPSSMapping                   ──────► Exploit prediction               │
│                                                                              │
│  Section D: Threat Intelligence                                              │
│  ├── STIXBundle export             ──────► TI platform sharing              │
│  ├── KEVMapping                    ──────► CISA known exploited             │
│  └── ThreatActorSTIX               ──────► Actor intelligence               │
│                                                                              │
│  Section E: Purple Team                                                      │
│  ├── AtomicTestMapping             ──────► ART validation                   │
│  ├── DetectionCoverageMatrix       ──────► ATT&CK heatmap                   │
│  └── PurpleExercise                ──────► Exercise planning                │
│                                                                              │
│  Section F: Security Metrics                                                 │
│  ├── SecurityMetrics               ──────► MTTD/MTTR tracking               │
│  └── CoverageMetrics               ──────► Attack surface coverage          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Model

### Section A: OWASP ASI Support

#### OWASPCategory Extension

```go
const (
    OWASPCategoryAPI     OWASPCategory = "api"     // API Security Top 10 (2023)
    OWASPCategoryLLM     OWASPCategory = "llm"     // LLM Application Top 10 (2025)
    OWASPCategoryWeb     OWASPCategory = "web"     // Web Application Top 10 (2021)
    OWASPCategoryAgentic OWASPCategory = "agentic" // Agentic Applications Top 10 (2026)
)
```

#### OWASP Reference Data (`ir/owasp_reference.go`)

```go
type OWASPEntry struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`
    Description string        `json:"description"`
    Category    OWASPCategory `json:"category"`
    URL         string        `json:"url"`
}

// 40 entries across 4 categories
var OWASPAPITop10 map[string]OWASPEntry     // 10 entries
var OWASPLLMTop10 map[string]OWASPEntry     // 10 entries
var OWASPWebTop10 map[string]OWASPEntry     // 10 entries
var OWASPAgenticTop10 map[string]OWASPEntry // 10 entries
```

### Section B: Role-Based Security Data

#### Red Team Types (`ir/redteam.go`)

```go
type ExploitationGuidance struct {
    Prerequisites      []string           `json:"prerequisites,omitempty"`
    ExploitationSteps  []ExploitationStep `json:"exploitationSteps,omitempty"`
    Tools              []OffensiveTool    `json:"tools,omitempty"`
    PayloadPatterns    []PayloadPattern   `json:"payloadPatterns,omitempty"`
    SuccessIndicators  []string           `json:"successIndicators,omitempty"`
    Difficulty         ExploitDifficulty  `json:"difficulty,omitempty"`
    TestRefs           []TestReference    `json:"testRefs,omitempty"`
}

type ExploitDifficulty string // trivial, low, medium, high, expert
```

#### Blue Team Types (`ir/blueteam.go`)

```go
type DefenseGuidance struct {
    DetectionRules            []DetectionRule  `json:"detectionRules,omitempty"`
    IOCs                      []IOC            `json:"iocs,omitempty"`
    LogSources                []LogSource      `json:"logSources,omitempty"`
    HuntingQueries            []HuntingQuery   `json:"huntingQueries,omitempty"`
    MonitoringRecommendations []string         `json:"monitoringRecommendations,omitempty"`
}

type DetectionFormat string // sigma, yara, splunk, elastic, kql, snort, suricata
type IOCType string         // ip, domain, url, hash, filepath, email, registry, process
```

#### Remediation Types (`ir/remediation.go`)

```go
type RemediationGuidance struct {
    VulnerablePatterns   []CodePattern      `json:"vulnerablePatterns,omitempty"`
    SecurePatterns       []CodePattern      `json:"securePatterns,omitempty"`
    ReviewChecklist      []ChecklistItem    `json:"reviewChecklist,omitempty"`
    RecommendedLibraries []Library          `json:"recommendedLibraries,omitempty"`
    ConfigurationChanges []ConfigChange     `json:"configurationChanges,omitempty"`
    TestingApproach      *TestingApproach   `json:"testingApproach,omitempty"`
}
```

#### Playbook Types (`ir/playbook.go`)

```go
type IncidentPlaybook struct {
    ID          string         `json:"id"`
    Name        string         `json:"name"`
    ThreatType  string         `json:"threatType,omitempty"`
    Steps       []PlaybookStep `json:"steps,omitempty"`
    Contacts    []Contact      `json:"contacts,omitempty"`
    SLAMinutes  int            `json:"slaMinutes,omitempty"`
}

type PlaybookPhase string // preparation, identification, containment, eradication, recovery, lessons-learned
```

#### Test Reference Types (`ir/testref.go`)

```go
type TestReference struct {
    TestID      string      `json:"testId"`
    TestFile    string      `json:"testFile,omitempty"`
    Purpose     TestPurpose `json:"purpose"`
    Description string      `json:"description,omitempty"`
}

type TestPurpose string // exploitation, detection, remediation, regression
```

### Section C: Risk Quantification

#### FAIR Types (`ir/fair.go`) - NEW

```go
type FAIRAssessment struct {
    // Loss Event Frequency
    ThreatEventFrequency  *FrequencyEstimate `json:"threatEventFrequency,omitempty"`
    Vulnerability         *Percentage        `json:"vulnerability,omitempty"`

    // Loss Magnitude
    PrimaryLoss           *LossEstimate      `json:"primaryLoss,omitempty"`
    SecondaryLoss         *LossEstimate      `json:"secondaryLoss,omitempty"`

    // Derived
    AnnualizedLossExpectancy *Currency       `json:"annualizedLossExpectancy,omitempty"`
    RiskScore             float64            `json:"riskScore,omitempty"`
}

type FrequencyEstimate struct {
    Min      float64 `json:"min"`
    Max      float64 `json:"max"`
    MostLikely float64 `json:"mostLikely"`
    Confidence string  `json:"confidence,omitempty"` // high, medium, low
}

type LossEstimate struct {
    Min      float64 `json:"min"`
    Max      float64 `json:"max"`
    MostLikely float64 `json:"mostLikely"`
    Currency string  `json:"currency,omitempty"` // USD, EUR, etc.
}

type BusinessImpact struct {
    RevenueImpact     *LossEstimate `json:"revenueImpact,omitempty"`
    CustomerImpact    string        `json:"customerImpact,omitempty"`
    RegulatoryImpact  string        `json:"regulatoryImpact,omitempty"`
    ReputationImpact  string        `json:"reputationImpact,omitempty"`
    OperationalImpact string        `json:"operationalImpact,omitempty"`
    Criticality       string        `json:"criticality,omitempty"` // critical, high, medium, low
}
```

#### EPSS Types (`ir/epss.go`) - NEW

```go
type EPSSData struct {
    CVE         string    `json:"cve"`
    EPSSScore   float64   `json:"epssScore"`   // 0.0 - 1.0
    Percentile  float64   `json:"percentile"`  // 0.0 - 100.0
    DateScored  string    `json:"dateScored,omitempty"`
}
```

### Section D: Threat Intelligence

#### STIX Export Types (`ir/stix_export.go`) - NEW

```go
type STIXExportOptions struct {
    IncludeIndicators   bool `json:"includeIndicators,omitempty"`
    IncludeAttackPatterns bool `json:"includeAttackPatterns,omitempty"`
    IncludeThreatActors bool `json:"includeThreatActors,omitempty"`
    IncludeMalware      bool `json:"includeMalware,omitempty"`
    IncludeTools        bool `json:"includeTools,omitempty"`
}

// Functions
func (tm *ThreatModel) ExportSTIXBundle(opts STIXExportOptions) (*stix.Bundle, error)
func (ioc *IOC) ToSTIXIndicator() *stix.Indicator
func (ta *ThreatActor) ToSTIXThreatActor() *stix.ThreatActor
```

#### KEV Types (`ir/kev.go`) - NEW

```go
type KEVEntry struct {
    CVEID              string `json:"cveId"`
    VendorProject      string `json:"vendorProject"`
    Product            string `json:"product"`
    VulnerabilityName  string `json:"vulnerabilityName"`
    DateAdded          string `json:"dateAdded"`
    ShortDescription   string `json:"shortDescription"`
    RequiredAction     string `json:"requiredAction"`
    DueDate            string `json:"dueDate"`
    KnownRansomware    bool   `json:"knownRansomwareCampaignUse"`
}

// Function
func GetKEVEntry(cveID string) *KEVEntry
func IsInKEV(cveID string) bool
```

### Section E: Purple Team

#### Atomic Red Team Types (`ir/atomicredteam.go`) - NEW

```go
type AtomicTestMapping struct {
    TechniqueID string   `json:"techniqueId"` // e.g., T1059.001
    AtomicTests []string `json:"atomicTests"` // e.g., ["T1059.001-1", "T1059.001-2"]
    Validated   bool     `json:"validated,omitempty"`
    LastRun     string   `json:"lastRun,omitempty"`
    Result      string   `json:"result,omitempty"` // passed, failed, blocked
}
```

#### Detection Coverage Types (`ir/coverage.go`) - NEW

```go
type DetectionCoverageMatrix struct {
    Techniques []TechniqueCoverage `json:"techniques"`
    Summary    *CoverageSummary    `json:"summary,omitempty"`
}

type TechniqueCoverage struct {
    TechniqueID   string  `json:"techniqueId"`
    TechniqueName string  `json:"techniqueName"`
    Tactic        string  `json:"tactic"`
    Coverage      string  `json:"coverage"` // none, partial, full
    DetectionIDs  []string `json:"detectionIds,omitempty"`
    Notes         string  `json:"notes,omitempty"`
}

type CoverageSummary struct {
    TotalTechniques   int     `json:"totalTechniques"`
    CoveredFull       int     `json:"coveredFull"`
    CoveredPartial    int     `json:"coveredPartial"`
    NotCovered        int     `json:"notCovered"`
    CoveragePercent   float64 `json:"coveragePercent"`
}
```

### Section F: Security Metrics

#### Metrics Types (`ir/metrics.go`) - NEW

```go
type SecurityMetrics struct {
    MTTD          *Duration `json:"mttd,omitempty"`          // Mean Time to Detect
    MTTR          *Duration `json:"mttr,omitempty"`          // Mean Time to Respond
    MTTC          *Duration `json:"mttc,omitempty"`          // Mean Time to Contain
    DetectionRate float64   `json:"detectionRate,omitempty"` // 0.0 - 1.0
    FalsePositiveRate float64 `json:"falsePositiveRate,omitempty"`
    MeasuredAt    string    `json:"measuredAt,omitempty"`
}

type Duration struct {
    Value int    `json:"value"`
    Unit  string `json:"unit"` // seconds, minutes, hours, days
}
```

### ThreatModel Additions

```go
type ThreatModel struct {
    // ... existing fields ...

    // Section A: OWASP (existing, enhanced)
    // Mappings.OWASP now includes agentic category

    // Section B: Role-Based Security Data
    RedTeam     *ExploitationGuidance  `json:"redTeam,omitempty"`
    BlueTeam    *DefenseGuidance       `json:"blueTeam,omitempty"`
    Remediation *RemediationGuidance   `json:"remediation,omitempty"`
    Playbooks   []IncidentPlaybook     `json:"playbooks,omitempty"`
    TestSuites  []TestSuiteReference   `json:"testSuites,omitempty"`

    // Section C: Risk Quantification
    RiskAssessment *FAIRAssessment    `json:"riskAssessment,omitempty"`
    BusinessImpact *BusinessImpact    `json:"businessImpact,omitempty"`
    EPSSData       []EPSSData         `json:"epssData,omitempty"`

    // Section D: Threat Intelligence
    // (Export functions, not stored fields)

    // Section E: Purple Team
    AtomicTests       []AtomicTestMapping      `json:"atomicTests,omitempty"`
    DetectionCoverage *DetectionCoverageMatrix `json:"detectionCoverage,omitempty"`

    // Section F: Security Metrics
    Metrics *SecurityMetrics `json:"metrics,omitempty"`
}
```

### Attack Additions

```go
type Attack struct {
    // ... existing fields ...

    // Role-based notes
    RedTeamNotes    string         `json:"redTeamNotes,omitempty"`
    BlueTeamNotes   string         `json:"blueTeamNotes,omitempty"`
    RemediationNote string         `json:"remediationNote,omitempty"`
    TestRef         *TestReference `json:"testRef,omitempty"`
}
```

## Files Summary

### New Files

| File | Section | Purpose |
|------|---------|---------|
| `ir/owasp_reference.go` | A | 40 OWASP entries |
| `ir/redteam.go` | B | Exploitation guidance |
| `ir/blueteam.go` | B | Defense guidance |
| `ir/remediation.go` | B | Code fix guidance |
| `ir/playbook.go` | B | IR playbooks |
| `ir/testref.go` | B | app-test-spec integration |
| `ir/fair.go` | C | FAIR risk assessment |
| `ir/epss.go` | C | EPSS scoring |
| `ir/stix_export.go` | D | STIX 2.1 export |
| `ir/kev.go` | D | KEV catalog |
| `ir/atomicredteam.go` | E | ART mapping |
| `ir/coverage.go` | E | Detection coverage |
| `ir/metrics.go` | F | Security metrics |

### Modified Files

| File | Changes |
|------|---------|
| `ir/mappings.go` | OWASPCategoryAgentic |
| `ir/diagram.go` | ASIIds, role notes, TestRef on Attack |
| `ir/threat_model.go` | All new ThreatModel fields |
| `ir/validate.go` | ValidateOWASPMappings() |

## Backward Compatibility

- All new fields use `omitempty` tag
- Existing ThreatModel and DiagramIR JSON remains valid
- No changes to existing required fields
- Version bump to v0.6.0 for schema
