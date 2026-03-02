// tms (Threat Model Spec) is a CLI for creating security threat modeling diagrams.
//
// Usage:
//
//	tms generate input.json -o output.d2        # Generate D2 diagram
//	tms generate input.json -o output.d2 --svg  # Also render to SVG
//	tms generate input.json --stix -o out.json  # Export to STIX 2.1
//	tms validate input.json                     # Validate only
//	tms validate input.json --strict            # Strict validation
package main

import (
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

// Generate command flags
var (
	outputFile string
	renderSVG  bool
	exportSTIX bool
)

// Validate command flags
var strictValidation bool

func init() {
	// Generate command flags
	generateCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	generateCmd.Flags().BoolVar(&renderSVG, "svg", false, "Also render to SVG using d2 CLI")
	generateCmd.Flags().BoolVar(&exportSTIX, "stix", false, "Export to STIX 2.1 format")

	// Validate command flags
	validateCmd.Flags().BoolVar(&strictValidation, "strict", false, "Use strict validation (includes warnings)")

	// Add subcommands
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runGenerate(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Load JSON
	diagram, err := ir.LoadFromFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	// Validate
	if err := diagram.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
		os.Exit(1)
	}

	if exportSTIX {
		// Export to STIX 2.1
		exporter := stix.NewExporter()
		stixJSON, err := exporter.ExportJSON(diagram)
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
		// Generate D2
		d2Content := diagram.RenderD2()

		if outputFile == "" {
			fmt.Print(d2Content)
		} else {
			if err := os.WriteFile(outputFile, []byte(d2Content), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outputFile, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Generated D2: %s\n", outputFile)

			// Optionally render to SVG
			if renderSVG {
				svgPath := strings.TrimSuffix(outputFile, ".d2") + ".svg"
				cmd := exec.Command("d2", outputFile, svgPath)
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

func runValidate(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Load JSON
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
