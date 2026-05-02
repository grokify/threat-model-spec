package ir

// SSVCExploitation represents the exploitation status in SSVC
type SSVCExploitation string

const (
	SSVCExploitationNone   SSVCExploitation = "none"
	SSVCExploitationPOC    SSVCExploitation = "poc"
	SSVCExploitationActive SSVCExploitation = "active"
)

// SSVCAutomatable represents whether the vulnerability is automatable
type SSVCAutomatable string

const (
	SSVCAutomatableNo  SSVCAutomatable = "no"
	SSVCAutomatableYes SSVCAutomatable = "yes"
)

// SSVCTechnicalImpact represents the technical impact of exploitation
type SSVCTechnicalImpact string

const (
	SSVCTechnicalImpactPartial SSVCTechnicalImpact = "partial"
	SSVCTechnicalImpactTotal   SSVCTechnicalImpact = "total"
)

// SSVCMissionPrevalence represents how prevalent the mission/system is
type SSVCMissionPrevalence string

const (
	SSVCMissionPrevalenceMinimal   SSVCMissionPrevalence = "minimal"
	SSVCMissionPrevalenceSupport   SSVCMissionPrevalence = "support"
	SSVCMissionPrevalenceEssential SSVCMissionPrevalence = "essential"
)

// SSVCPublicWellBeing represents impact on public well-being/safety
type SSVCPublicWellBeing string

const (
	SSVCPublicWellBeingMinimal      SSVCPublicWellBeing = "minimal"
	SSVCPublicWellBeingMaterial     SSVCPublicWellBeing = "material"
	SSVCPublicWellBeingIrreversible SSVCPublicWellBeing = "irreversible"
)

// SSVCDecision represents the SSVC decision outcome
type SSVCDecision string

const (
	// SSVCDecisionTrack - continue tracking, no immediate action needed
	SSVCDecisionTrack SSVCDecision = "track"

	// SSVCDecisionTrackStar - track closely, slightly elevated priority
	SSVCDecisionTrackStar SSVCDecision = "track*"

	// SSVCDecisionAttend - attend to this vulnerability soon
	SSVCDecisionAttend SSVCDecision = "attend"

	// SSVCDecisionAct - act immediately, highest priority
	SSVCDecisionAct SSVCDecision = "act"
)

// SSVCAssessment represents a Stakeholder-Specific Vulnerability Categorization assessment
type SSVCAssessment struct {
	// VulnerabilityID is the CVE or other vulnerability identifier
	VulnerabilityID string `json:"vulnerabilityId,omitempty"`

	// Exploitation status (none, poc, active)
	Exploitation SSVCExploitation `json:"exploitation,omitempty"`

	// Automatable indicates if exploitation can be automated (no, yes)
	Automatable SSVCAutomatable `json:"automatable,omitempty"`

	// TechnicalImpact of successful exploitation (partial, total)
	TechnicalImpact SSVCTechnicalImpact `json:"technicalImpact,omitempty"`

	// MissionPrevalence indicates mission/business criticality (minimal, support, essential)
	MissionPrevalence SSVCMissionPrevalence `json:"missionPrevalence,omitempty"`

	// PublicWellBeing indicates impact on public safety (minimal, material, irreversible)
	PublicWellBeing SSVCPublicWellBeing `json:"publicWellBeing,omitempty"`

	// Decision is the calculated SSVC decision (track, track*, attend, act)
	Decision SSVCDecision `json:"decision,omitempty"`

	// Notes provides additional context for the assessment
	Notes string `json:"notes,omitempty"`

	// AssessedAt is when this assessment was made
	AssessedAt string `json:"assessedAt,omitempty"`

	// AssessedBy is who performed this assessment
	AssessedBy string `json:"assessedBy,omitempty"`
}

// CalculateSSVCDecision calculates the SSVC decision based on input factors
// This implements the CISA SSVC decision tree for prioritizing vulnerabilities
func CalculateSSVCDecision(
	exploitation SSVCExploitation,
	automatable SSVCAutomatable,
	technicalImpact SSVCTechnicalImpact,
	missionPrevalence SSVCMissionPrevalence,
	publicWellBeing SSVCPublicWellBeing,
) SSVCDecision {
	// If there's active exploitation, escalate based on impact
	if exploitation == SSVCExploitationActive {
		if technicalImpact == SSVCTechnicalImpactTotal {
			return SSVCDecisionAct
		}
		if missionPrevalence == SSVCMissionPrevalenceEssential ||
			publicWellBeing == SSVCPublicWellBeingIrreversible {
			return SSVCDecisionAct
		}
		return SSVCDecisionAttend
	}

	// POC exploitation with automation capability
	if exploitation == SSVCExploitationPOC {
		if automatable == SSVCAutomatableYes {
			if technicalImpact == SSVCTechnicalImpactTotal {
				return SSVCDecisionAttend
			}
			if missionPrevalence == SSVCMissionPrevalenceEssential {
				return SSVCDecisionAttend
			}
			if publicWellBeing == SSVCPublicWellBeingIrreversible {
				return SSVCDecisionAttend
			}
			return SSVCDecisionTrackStar
		}
		// POC but not automatable
		if missionPrevalence == SSVCMissionPrevalenceEssential &&
			technicalImpact == SSVCTechnicalImpactTotal {
			return SSVCDecisionTrackStar
		}
		return SSVCDecisionTrack
	}

	// No known exploitation
	if automatable == SSVCAutomatableYes &&
		technicalImpact == SSVCTechnicalImpactTotal &&
		missionPrevalence == SSVCMissionPrevalenceEssential {
		return SSVCDecisionTrackStar
	}

	return SSVCDecisionTrack
}

// Calculate computes and sets the Decision field based on other assessment fields
func (a *SSVCAssessment) Calculate() {
	a.Decision = CalculateSSVCDecision(
		a.Exploitation,
		a.Automatable,
		a.TechnicalImpact,
		a.MissionPrevalence,
		a.PublicWellBeing,
	)
}

// IsHighPriority returns true if the decision is attend or act
func (a *SSVCAssessment) IsHighPriority() bool {
	return a.Decision == SSVCDecisionAttend || a.Decision == SSVCDecisionAct
}

// RequiresImmediateAction returns true if the decision is act
func (a *SSVCAssessment) RequiresImmediateAction() bool {
	return a.Decision == SSVCDecisionAct
}

// NewSSVCAssessment creates a new SSVC assessment and calculates the decision
func NewSSVCAssessment(
	vulnID string,
	exploitation SSVCExploitation,
	automatable SSVCAutomatable,
	technicalImpact SSVCTechnicalImpact,
	missionPrevalence SSVCMissionPrevalence,
	publicWellBeing SSVCPublicWellBeing,
) *SSVCAssessment {
	assessment := &SSVCAssessment{
		VulnerabilityID:   vulnID,
		Exploitation:      exploitation,
		Automatable:       automatable,
		TechnicalImpact:   technicalImpact,
		MissionPrevalence: missionPrevalence,
		PublicWellBeing:   publicWellBeing,
	}
	assessment.Calculate()
	return assessment
}
