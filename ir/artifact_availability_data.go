package ir

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed artifactavailability/*.json
var artifactAvailabilityFS embed.FS

// allAnalysisRunProfiles lists the three profile IDs in a stable order,
// matching their embedded filenames.
func allAnalysisRunProfiles() []AnalysisRunProfile {
	return []AnalysisRunProfile{
		AnalysisRunProfileFirstParty,
		AnalysisRunProfileThirdParty,
		AnalysisRunProfileOpenSource,
	}
}

// ArtifactAvailabilityProfiles returns the three canonical
// ArtifactAvailabilityProfile definitions: first-party, third-party, and
// open-source, in that order.
func ArtifactAvailabilityProfiles() ([]ArtifactAvailabilityProfile, error) {
	profiles := make([]ArtifactAvailabilityProfile, 0, 3)
	for _, p := range allAnalysisRunProfiles() {
		ap, err := ArtifactAvailabilityProfileByProfile(p)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, ap)
	}
	return profiles, nil
}

// ArtifactAvailabilityProfileByProfile returns the ArtifactAvailabilityProfile
// for a single AnalysisRunProfile.
func ArtifactAvailabilityProfileByProfile(profile AnalysisRunProfile) (ArtifactAvailabilityProfile, error) {
	data, err := artifactAvailabilityFS.ReadFile("artifactavailability/" + string(profile) + ".json")
	if err != nil {
		return ArtifactAvailabilityProfile{}, fmt.Errorf("no embedded artifact-availability profile %q: %w", profile, err)
	}
	var p ArtifactAvailabilityProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return ArtifactAvailabilityProfile{}, fmt.Errorf("parsing artifact-availability profile %q: %w", profile, err)
	}
	return p, nil
}

// MustArtifactAvailabilityProfiles returns the three
// ArtifactAvailabilityProfile definitions and panics if the embedded data
// is invalid — a build-time defect, not a runtime condition.
func MustArtifactAvailabilityProfiles() []ArtifactAvailabilityProfile {
	profiles, err := ArtifactAvailabilityProfiles()
	if err != nil {
		panic(err)
	}
	return profiles
}
