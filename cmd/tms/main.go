// tms (Threat Model Spec) is a CLI for creating security threat modeling diagrams.
//
// Usage:
//
//	tms generate input.json -o output.d2        # Generate D2 diagram
//	tms generate input.json -o output.d2 -svg   # Also render to SVG
//	tms generate input.json --stix -o out.json  # Export to STIX 2.1
//	tms validate input.json                     # Validate only
//	tms validate input.json -strict             # Strict validation
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/grokify/threat-model-spec/ir"
	"github.com/grokify/threat-model-spec/stix"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "generate":
		generateCmd(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	case "version":
		fmt.Printf("tms version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`tms - Threat Model Spec CLI

Usage:
  tms <command> [options] <input.json>

Commands:
  generate    Generate D2 diagram or STIX 2.1 from JSON
  validate    Validate a threat model JSON file
  version     Print version information
  help        Print this help message

Generate Options:
  -o <file>   Output file (default: stdout)
  -svg        Also render to SVG using d2 CLI
  --stix      Export to STIX 2.1 format instead of D2

Validate Options:
  -strict     Use strict validation (includes warnings)

Examples:
  tms generate attack.json -o attack.d2
  tms generate attack.json -o attack.d2 -svg
  tms generate attack.json --stix -o attack.stix.json
  tms validate attack.json
  tms validate attack.json -strict`)
}

func generateCmd(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	output := fs.String("o", "", "Output file (default: stdout)")
	renderSVG := fs.Bool("svg", false, "Also render to SVG using d2 CLI")
	exportSTIX := fs.Bool("stix", false, "Export to STIX 2.1 format")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: tms generate [-o output] [-svg] [--stix] <input.json>")
		os.Exit(1)
	}

	inputPath := fs.Arg(0)

	// Load JSON
	diagram, err := ir.LoadFromFile(inputPath)
	if err != nil {
		log.Fatalf("Error loading %s: %v", inputPath, err)
	}

	// Validate
	if err := diagram.Validate(); err != nil {
		log.Fatalf("Validation failed: %v", err)
	}

	if *exportSTIX {
		// Export to STIX 2.1
		exporter := stix.NewExporter()
		stixJSON, err := exporter.ExportJSON(diagram)
		if err != nil {
			log.Fatalf("Error exporting to STIX: %v", err)
		}

		if *output == "" {
			fmt.Println(stixJSON)
		} else {
			if err := os.WriteFile(*output, []byte(stixJSON), 0644); err != nil {
				log.Fatalf("Error writing %s: %v", *output, err)
			}
			fmt.Fprintf(os.Stderr, "Generated STIX: %s\n", *output)
		}
	} else {
		// Generate D2
		d2Content := diagram.RenderD2()

		if *output == "" {
			fmt.Print(d2Content)
		} else {
			if err := os.WriteFile(*output, []byte(d2Content), 0644); err != nil {
				log.Fatalf("Error writing %s: %v", *output, err)
			}
			fmt.Fprintf(os.Stderr, "Generated D2: %s\n", *output)

			// Optionally render to SVG
			if *renderSVG {
				svgPath := strings.TrimSuffix(*output, ".d2") + ".svg"
				cmd := exec.Command("d2", *output, svgPath)
				cmdOutput, err := cmd.CombinedOutput()
				if err != nil {
					log.Fatalf("Error rendering SVG: %v\n%s", err, cmdOutput)
				}
				fmt.Fprintf(os.Stderr, "Generated SVG: %s\n", svgPath)
			}
		}
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	strict := fs.Bool("strict", false, "Use strict validation (includes warnings)")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: tms validate [-strict] <input.json>")
		os.Exit(1)
	}

	inputPath := fs.Arg(0)

	// Load JSON
	diagram, err := ir.LoadFromFile(inputPath)
	if err != nil {
		log.Fatalf("Error loading %s: %v", inputPath, err)
	}

	// Validate
	if *strict {
		if err := diagram.ValidateStrict(); err != nil {
			log.Fatalf("Strict validation failed: %v", err)
		}
		fmt.Printf("Strict validation passed: %s\n", inputPath)
	} else {
		if err := diagram.Validate(); err != nil {
			log.Fatalf("Validation failed: %v", err)
		}
		fmt.Printf("Validation passed: %s\n", inputPath)
	}
}
