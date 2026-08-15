package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/grokify/threat-model-spec/ir"
)

// tms profile is a pure read command printing a built-in
// ArtifactAvailabilityProfile definition — what artifacts that profile
// assumes are available, and which PDLC stages are (and are not)
// analyzable under it. Static data, no model file involved.
var profileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Print an artifact-availability profile definition",
	Long: `Print a built-in ArtifactAvailabilityProfile: which artifact types it
assumes are available, and which PDLC stages are permitted or explicitly
not analyzable under it, with reasons.`,
	Args: cobra.ExactArgs(1),
	Run:  runProfile,
	Example: `  tms profile first-party
  tms profile third-party --json`,
}

var profileJSON bool

func init() {
	profileCmd.Flags().BoolVar(&profileJSON, "json", false, "Output as JSON")

	rootCmd.AddCommand(profileCmd)
}

func runProfile(_ *cobra.Command, args []string) {
	name := args[0]

	profile, err := ir.ArtifactAvailabilityProfileByProfile(ir.AnalysisRunProfile(name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unknown artifact-availability profile %q (want first-party, third-party, or open-source): %v\n", name, err)
		os.Exit(1)
	}

	if profileJSON {
		data, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding profile: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Profile: %s\n", profile.Profile)
	if profile.Description != "" {
		fmt.Printf("%s\n", profile.Description)
	}
	fmt.Println()

	fmt.Println("Available artifact types:")
	if len(profile.AvailableArtifactTypes) == 0 {
		fmt.Println("  (none)")
	}
	for _, at := range profile.AvailableArtifactTypes {
		fmt.Printf("  - %s\n", at)
	}
	fmt.Println()

	fmt.Println("Permitted stages:")
	if len(profile.PermittedStages) == 0 {
		fmt.Println("  (none)")
	}
	for _, s := range profile.PermittedStages {
		fmt.Printf("  - %s\n", s)
	}

	if len(profile.NotAnalyzableStages) > 0 {
		fmt.Println()
		fmt.Println("Not analyzable:")
		for _, n := range profile.NotAnalyzableStages {
			fmt.Printf("  - %s: %s\n", n.Stage, n.Reason)
		}
	}
}
