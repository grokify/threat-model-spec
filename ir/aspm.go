package ir

import "github.com/invopop/jsonschema"

// ASPMDomainID identifies one of the ten Application Security Posture
// Management (ASPM) domains. Each domain overlays exactly one of the three
// builder-side PDLC stages (Implementation, Deployment, Builder Operations)
// as its PrimaryStage. Domains near a stage seam (git posture, SBOM,
// CI/CD posture, IaC scan) carry a primary stage, but their evidence may
// still attach to an adjacent stage — PrimaryStage is a default, not a hard
// partition.
type ASPMDomainID string

const (
	// ASPMDomainGitPosture covers repository security posture: branch
	// protection, signed commits, access controls.
	ASPMDomainGitPosture ASPMDomainID = "git-posture"

	// ASPMDomainCodeSecurity covers static application security testing
	// (SAST) findings in source code.
	ASPMDomainCodeSecurity ASPMDomainID = "code-security"

	// ASPMDomainSecretPIIScan covers committed secrets and exposed PII.
	ASPMDomainSecretPIIScan ASPMDomainID = "secret-pii-scan"

	// ASPMDomainOpenSourceSecurity covers software composition analysis
	// (SCA): vulnerable and risky open-source dependencies.
	ASPMDomainOpenSourceSecurity ASPMDomainID = "open-source-security"

	// ASPMDomainSBOM covers software bill of materials generation and
	// completeness.
	ASPMDomainSBOM ASPMDomainID = "sbom"

	// ASPMDomainIaCScan covers infrastructure-as-code misconfiguration
	// scanning.
	ASPMDomainIaCScan ASPMDomainID = "iac-scan"

	// ASPMDomainCICDPosture covers CI/CD pipeline security: build
	// provenance, pipeline permissions, secrets handling in CI.
	ASPMDomainCICDPosture ASPMDomainID = "cicd-posture"

	// ASPMDomainContainerSecurity covers container image scanning and
	// runtime container posture.
	ASPMDomainContainerSecurity ASPMDomainID = "container-security"

	// ASPMDomainArtifactSecurity covers build-artifact integrity and
	// provenance (e.g. signing, attestation).
	ASPMDomainArtifactSecurity ASPMDomainID = "artifact-security"

	// ASPMDomainCloudContext covers deployed cloud/runtime security
	// posture (CSPM): IAM, network exposure, logging.
	ASPMDomainCloudContext ASPMDomainID = "cloud-context"
)

// JSONSchema implements jsonschema.JSONSchemaer for ASPMDomainID.
func (ASPMDomainID) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"git-posture",
			"code-security",
			"secret-pii-scan",
			"open-source-security",
			"sbom",
			"iac-scan",
			"cicd-posture",
			"container-security",
			"artifact-security",
			"cloud-context",
		},
	}
}

// ASPMDomain describes one ASPM domain and the PDLC stage it primarily
// overlays.
type ASPMDomain struct {
	// ID is the canonical domain identifier.
	ID ASPMDomainID `json:"id"`

	// Name is the human-readable domain name.
	Name string `json:"name"`

	// Description explains what this domain covers.
	Description string `json:"description,omitempty"`

	// PrimaryStage is the PDLC stage this domain's findings are organized
	// under by default. Always Implementation, Deployment, or
	// BuilderOperations.
	PrimaryStage Stage `json:"primaryStage"`
}

// ASPMDomains returns the ten canonical ASPM domains, in a stable order
// grouped by primary stage (Implementation, then Deployment, then Builder
// Operations).
func ASPMDomains() []ASPMDomain {
	return []ASPMDomain{
		{ID: ASPMDomainGitPosture, Name: "Git Posture", Description: "Repository security posture: branch protection, signed commits, access controls", PrimaryStage: StageImplementation},
		{ID: ASPMDomainCodeSecurity, Name: "Code Security", Description: "Static application security testing (SAST) findings in source code", PrimaryStage: StageImplementation},
		{ID: ASPMDomainSecretPIIScan, Name: "Secret/PII Scan", Description: "Committed secrets and exposed personally identifiable information", PrimaryStage: StageImplementation},
		{ID: ASPMDomainOpenSourceSecurity, Name: "Open Source Security", Description: "Software composition analysis (SCA): vulnerable and risky open-source dependencies", PrimaryStage: StageImplementation},
		{ID: ASPMDomainSBOM, Name: "SBOM", Description: "Software bill of materials generation and completeness", PrimaryStage: StageImplementation},
		{ID: ASPMDomainIaCScan, Name: "Infrastructure as Code Scan", Description: "Infrastructure-as-code misconfiguration scanning", PrimaryStage: StageDeployment},
		{ID: ASPMDomainCICDPosture, Name: "CI/CD Posture", Description: "CI/CD pipeline security: build provenance, pipeline permissions, secrets handling in CI", PrimaryStage: StageDeployment},
		{ID: ASPMDomainContainerSecurity, Name: "Container Security", Description: "Container image scanning and runtime container posture", PrimaryStage: StageDeployment},
		{ID: ASPMDomainArtifactSecurity, Name: "Artifact Security", Description: "Build-artifact integrity and provenance (signing, attestation)", PrimaryStage: StageDeployment},
		{ID: ASPMDomainCloudContext, Name: "Cloud Context", Description: "Deployed cloud/runtime security posture (CSPM): IAM, network exposure, logging", PrimaryStage: StageBuilderOperations},
	}
}

// ASPMDomainByID looks up a canonical ASPM domain by ID.
func ASPMDomainByID(id ASPMDomainID) (ASPMDomain, bool) {
	for _, d := range ASPMDomains() {
		if d.ID == id {
			return d, true
		}
	}
	return ASPMDomain{}, false
}
