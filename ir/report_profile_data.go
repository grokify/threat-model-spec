package ir

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed stagereports/*.json
var stageReportProfilesFS embed.FS

// StageReportProfiles returns the six canonical StageReportProfile
// definitions, one per PDLC stage, in pdlc's canonical stage order.
func StageReportProfiles() ([]StageReportProfile, error) {
	profiles := make([]StageReportProfile, 0, len(AllStages()))
	for _, stage := range AllStages() {
		p, err := StageReportProfileByStage(stage)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// StageReportProfileByStage returns the StageReportProfile for a single
// PDLC stage.
func StageReportProfileByStage(stage Stage) (StageReportProfile, error) {
	data, err := stageReportProfilesFS.ReadFile("stagereports/" + string(stage) + ".json")
	if err != nil {
		return StageReportProfile{}, fmt.Errorf("no embedded report profile for stage %q: %w", stage, err)
	}
	var p StageReportProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return StageReportProfile{}, fmt.Errorf("parsing report profile for stage %q: %w", stage, err)
	}
	return p, nil
}

// MustStageReportProfiles returns the six StageReportProfile definitions
// and panics if the embedded data is invalid — a build-time defect, not a
// runtime condition.
func MustStageReportProfiles() []StageReportProfile {
	profiles, err := StageReportProfiles()
	if err != nil {
		panic(err)
	}
	return profiles
}
