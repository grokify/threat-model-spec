package main

import (
	"encoding/json"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func resetProfileFlags() {
	profileJSON = false
}

func TestProfile_AllThreeProfiles(t *testing.T) {
	for _, name := range []string{"first-party", "third-party", "open-source"} {
		name := name
		t.Run(name, func(t *testing.T) {
			resetFlags()
			resetProfileFlags()

			rootCmd.SetArgs([]string{"profile", name})
			out := captureStdout(t, func() {
				if err := rootCmd.Execute(); err != nil {
					t.Fatalf("profile %s: %v", name, err)
				}
			})
			if out == "" {
				t.Error("profile produced no output")
			}
		})
	}
}

func TestProfile_JSONOutput(t *testing.T) {
	resetFlags()
	resetProfileFlags()

	rootCmd.SetArgs([]string{"profile", "third-party", "--json"})
	out := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("profile --json: %v", err)
		}
	})

	var profile ir.ArtifactAvailabilityProfile
	if err := json.Unmarshal([]byte(out), &profile); err != nil {
		t.Fatalf("unmarshaling profile JSON: %v\noutput: %s", err, out)
	}
	if profile.Profile != ir.AnalysisRunProfileThirdParty {
		t.Errorf("Profile = %q, want %q", profile.Profile, ir.AnalysisRunProfileThirdParty)
	}
	if len(profile.NotAnalyzableStages) == 0 {
		t.Error("third-party profile should have at least one not-analyzable stage")
	}
}
