// tms (Threat Model Spec) is a CLI for creating security threat modeling diagrams.
//
// Usage:
//
//	tms generate input.json -o output.d2        # Generate D2 diagram
//	tms generate input.json -o output.d2 --svg  # Also render to SVG
//	tms generate input.json --stix -o out.json  # Export to STIX 2.1
//	tms validate input.json                     # Validate only
//	tms validate input.json --strict            # Strict validation
//	tms analyze input.json --stage <s> ...      # PDLC stage analysis (plan/apply)
//	tms gate input.json --stage <s>             # Read a recorded stage gate result
//	tms report input.json --framework <f>       # Derive a framework-specific report
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/grokify/threat-model-spec/ir"
	"github.com/grokify/threat-model-spec/stix"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "tms",
	Short: "Threat Model Spec CLI",
	Long: `tms is a CLI tool for creating security threat modeling diagrams.

It converts JSON intermediate representation (IR) to D2 diagrams or STIX 2.1
bundles for threat intelligence sharing.

Supported diagram types:
  - DFD (Data Flow Diagram)
  - Attack Chain
  - Sequence Diagram

Framework mappings:
  - MITRE ATT&CK
  - MITRE ATLAS
  - OWASP Top 10 (API, LLM, Web)
  - CWE
  - CVSS
  - STRIDE`,
}

var generateCmd = &cobra.Command{
	Use:   "generate <input.json>",
	Short: "Generate D2 diagram or STIX 2.1 from JSON",
	Long: `Generate a D2 diagram or STIX 2.1 bundle from a threat model JSON file.

By default, outputs D2 diagram format. Use --stix to export to STIX 2.1 format instead.`,
	Args: cobra.ExactArgs(1),
	Run:  runGenerate,
	Example: `  tms generate attack.json -o attack.d2
  tms generate attack.json -o attack.d2 --svg
  tms generate attack.json --stix -o attack.stix.json`,
}

var validateCmd = &cobra.Command{
	Use:   "validate <input.json>",
	Short: "Validate a threat model JSON file",
	Long: `Validate the structure and content of a threat model JSON file.

Use --strict for strict validation that includes warnings for recommended fields.`,
	Args: cobra.ExactArgs(1),
	Run:  runValidate,
	Example: `  tms validate attack.json
  tms validate attack.json --strict`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("tms version %s\n", version)
	},
}

var gateCmd = &cobra.Command{
	Use:   "gate <input.json>",
	Short: "Evaluate a stage gate from recorded criteria",
	Long: `Print the recorded Gate result for a PDLC stage.

tms gate is read-only: it reports a Gate already recorded in the model's
"gates" array (written by an analysis run), it does not compute one. Use
--ci to exit non-zero when the gate has not passed — a gate with no
recorded result yet ("pending") is treated as not passing.`,
	Args: cobra.ExactArgs(1),
	Run:  runGate,
	Example: `  tms gate threat-model.json --stage deployment
  tms gate threat-model.json --stage deployment --ci`,
}

// Generate command flags
var (
	outputFile string
	renderSVG  bool
	exportSTIX bool
)

// Validate command flags
var strictValidation bool

// Gate command flags
var (
	gateStage string
	gateCI    bool
	gateJSON  bool
)

func init() {
	// Generate command flags
	generateCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	generateCmd.Flags().BoolVar(&renderSVG, "svg", false, "Also render to SVG using d2 CLI")
	generateCmd.Flags().BoolVar(&exportSTIX, "stix", false, "Export to STIX 2.1 format")

	// Validate command flags
	validateCmd.Flags().BoolVar(&strictValidation, "strict", false, "Use strict validation (includes warnings)")

	// Gate command flags
	gateCmd.Flags().StringVar(&gateStage, "stage", "", "PDLC stage to evaluate (required)")
	gateCmd.Flags().BoolVar(&gateCI, "ci", false, "Exit non-zero if the gate has not passed")
	gateCmd.Flags().BoolVar(&gateJSON, "json", false, "Output as JSON")
	_ = gateCmd.MarkFlagRequired("stage")

	// Add subcommands
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(gateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runGenerate(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Try to load as ThreatModel first, fall back to DiagramIR
	diagrams, isThreatModel, err := loadInput(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	if exportSTIX {
		// Export to STIX 2.1 (use first diagram for now, or could merge)
		if len(diagrams) == 0 {
			fmt.Fprintln(os.Stderr, "No diagrams to export")
			os.Exit(1)
		}
		exporter := stix.NewExporter()
		stixJSON, err := exporter.ExportJSON(diagrams[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to STIX: %v\n", err)
			os.Exit(1)
		}

		if outputFile == "" {
			fmt.Println(stixJSON)
		} else {
			if err := os.WriteFile(outputFile, []byte(stixJSON), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outputFile, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Generated STIX: %s\n", outputFile)
		}
	} else {
		// Generate D2 for each diagram
		for i, diagram := range diagrams {
			d2Content := diagram.RenderD2()

			// Determine output filename
			outPath := outputFile
			if isThreatModel && len(diagrams) > 1 && outputFile != "" {
				// Multiple diagrams: append diagram type to filename
				base := strings.TrimSuffix(outputFile, ".d2")
				outPath = fmt.Sprintf("%s_%s.d2", base, diagram.Type)
			}

			if outPath == "" {
				if i > 0 {
					fmt.Print("\n---\n\n") // Separator between diagrams
				}
				fmt.Print(d2Content)
			} else {
				if err := os.WriteFile(outPath, []byte(d2Content), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Generated D2: %s\n", outPath)

				// Optionally render to SVG
				if renderSVG {
					svgPath := strings.TrimSuffix(outPath, ".d2") + ".svg"
					cmd := exec.Command("d2", outPath, svgPath)
					cmdOutput, err := cmd.CombinedOutput()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error rendering SVG: %v\n%s", err, cmdOutput)
						os.Exit(1)
					}
					fmt.Fprintf(os.Stderr, "Generated SVG: %s\n", svgPath)
				}
			}
		}
	}
}

// loadInput loads either a ThreatModel or DiagramIR from a JSON file.
// Returns the diagrams, whether it was a ThreatModel, and any error.
func loadInput(path string) ([]*ir.DiagramIR, bool, error) {
	// Try ThreatModel first (check for "diagrams" array)
	tm, err := ir.LoadThreatModelFromFile(path)
	if err == nil && len(tm.Diagrams) > 0 {
		// Validate ThreatModel
		if err := tm.Validate(); err != nil {
			return nil, true, fmt.Errorf("validation failed: %w", err)
		}

		// Extract DiagramIR for each diagram view
		var diagrams []*ir.DiagramIR
		for _, dv := range tm.Diagrams {
			diagrams = append(diagrams, dv.ToDiagramIR(tm))
		}
		return diagrams, true, nil
	}

	// Fall back to DiagramIR
	diagram, err := ir.LoadFromFile(path)
	if err != nil {
		return nil, false, err
	}

	// Validate DiagramIR
	if err := diagram.Validate(); err != nil {
		return nil, false, fmt.Errorf("validation failed: %w", err)
	}

	return []*ir.DiagramIR{diagram}, false, nil
}

func runValidate(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Try ThreatModel first
	tm, err := ir.LoadThreatModelFromFile(inputPath)
	if err == nil && len(tm.Diagrams) > 0 {
		// Validate as ThreatModel
		if err := tm.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			os.Exit(1)
		}

		warnStaleFrameworkReports(tm)

		// For strict validation, also validate each diagram strictly
		if strictValidation {
			for _, dv := range tm.Diagrams {
				d := dv.ToDiagramIR(tm)
				if err := d.ValidateStrict(); err != nil {
					fmt.Fprintf(os.Stderr, "Strict validation failed for %s diagram: %v\n", dv.Type, err)
					os.Exit(1)
				}
			}
			fmt.Printf("Strict validation passed: %s (ThreatModel with %d diagrams)\n", inputPath, len(tm.Diagrams))
		} else {
			fmt.Printf("Validation passed: %s (ThreatModel with %d diagrams)\n", inputPath, len(tm.Diagrams))
		}
		return
	}

	// Fall back to DiagramIR
	diagram, err := ir.LoadFromFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	// Validate
	if strictValidation {
		if err := diagram.ValidateStrict(); err != nil {
			fmt.Fprintf(os.Stderr, "Strict validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Strict validation passed: %s\n", inputPath)
	} else {
		if err := diagram.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Validation passed: %s\n", inputPath)
	}
}

func runGate(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Belt-and-suspenders: don't rely solely on cobra's MarkFlagRequired
	// for --stage. An empty gateStage would otherwise silently match
	// nothing and print a confusing "no gate recorded" error.
	if gateStage == "" {
		fmt.Fprintln(os.Stderr, "Error: --stage is required")
		os.Exit(1)
	}

	tm, err := ir.LoadThreatModelFromFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	var gate *ir.Gate
	for i := range tm.Gates {
		if string(tm.Gates[i].Stage) == gateStage {
			gate = &tm.Gates[i]
			break
		}
	}
	if gate == nil {
		fmt.Fprintf(os.Stderr, "No gate recorded for stage %q in %s\n", gateStage, inputPath)
		os.Exit(1)
	}

	if gateJSON {
		data, err := json.MarshalIndent(gate, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding gate: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		printGate(*gate)
	}

	if gateCI && gate.Result != ir.GateResultPassed {
		os.Exit(1)
	}
}
