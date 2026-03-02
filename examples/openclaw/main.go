// Example: OpenClaw WebSocket Localhost Takeover
//
// This example demonstrates how to use the threat-model-spec library to programmatically
// create a threat model diagram for the OpenClaw vulnerability.
//
// Run:
//
//	go run main.go > attack_chain_generated.d2
//	d2 attack_chain_generated.d2 attack_chain_generated.svg
package main

import (
	"fmt"

	"github.com/grokify/threat-model-spec/diagram"
	"github.com/grokify/threat-model-spec/killchain"
	"github.com/grokify/threat-model-spec/stride"
)

func main() {
	// Create diagram
	d := diagram.New("OpenClaw WebSocket Localhost Takeover")
	d.Direction = diagram.DirectionRight

	// Add trust boundaries
	d.AddBoundary("browser-sandbox", "Browser Sandbox", diagram.BrowserBoundary)
	d.AddBoundary("localhost-zone", "Localhost (Implicit Trust)", diagram.LocalhostBoundary)

	// Add elements in browser sandbox
	d.AddElement("victim", "Victim Browser", diagram.Browser, "browser-sandbox")
	maliciousJS := d.AddElement("malicious-js", "Malicious JS", diagram.Process, "browser-sandbox")
	maliciousJS.Compromised = true

	// Add elements in localhost zone
	d.AddElement("gateway", "OpenClaw Gateway", diagram.Gateway, "localhost-zone")
	d.AddElement("agent", "AI Agent", diagram.AIAgent, "localhost-zone")
	d.AddElement("config", "Config & Logs", diagram.ConfigStore, "localhost-zone")
	d.AddElement("devices", "Connected Devices", diagram.Process, "localhost-zone")

	// Add external attacker
	attacker := d.AddElement("attacker-site", "Attacker Website", diagram.ExternalEntity, "")
	attacker.Compromised = true

	// Add flows - attack chain
	d.AddFlow("attacker-site", "browser-sandbox.victim", "1. Visits site", diagram.NormalFlow)
	d.AddFlow("browser-sandbox.victim", "browser-sandbox.malicious-js", "2. Loads JS", diagram.AttackFlow)

	// WebSocket attack flows
	f3 := d.AddAttackFlow("browser-sandbox.malicious-js", "localhost-zone.gateway", "3. WebSocket to localhost", 3)
	f3.Threats = []stride.Threat{{
		Type:        stride.Spoofing,
		Title:       "Localhost origin spoofing",
		Description: "Browser JS appears as legitimate localhost connection",
	}}
	f3.MITRETactic = killchain.InitialAccess
	f3.MITRETechnique = &killchain.Technique{
		ID:     "T1199",
		Name:   "Trusted Relationship",
		Tactic: killchain.InitialAccess,
	}

	f4 := d.AddAttackFlow("browser-sandbox.malicious-js", "localhost-zone.gateway", "4. Brute-force", 4)
	f4.Threats = []stride.Threat{{
		Type:        stride.ElevationOfPrivilege,
		Title:       "Rate limit bypass",
		Description: "No rate limiting for localhost connections",
	}}
	f4.MITRETactic = killchain.CredentialAccess

	d.AddAttackFlow("browser-sandbox.malicious-js", "localhost-zone.gateway", "5. Register device", 5)

	// Post-compromise flows
	d.AddAttackFlow("localhost-zone.gateway", "localhost-zone.agent", "6. Send commands", 6)

	f7 := d.AddAttackFlow("localhost-zone.agent", "localhost-zone.config", "7. Read config", 7)
	f7.Threats = []stride.Threat{{
		Type:        stride.InformationDisclosure,
		Title:       "Config and logs stolen",
		Description: "API keys, credentials, and logs exfiltrated",
	}}

	d.AddAttackFlow("localhost-zone.gateway", "localhost-zone.devices", "8. Enumerate", 8)

	// Exfiltration flows
	exfil := d.AddFlow("localhost-zone.gateway", "browser-sandbox.malicious-js", "9. Exfiltrate", diagram.ExfilFlow)
	exfil.MITRETactic = killchain.Exfiltration

	d.AddFlow("browser-sandbox.malicious-js", "attacker-site", "10. Send to attacker", diagram.ExfilFlow)

	// Add standalone threat annotations
	d.AddThreat(stride.Threat{
		Type:      stride.Spoofing,
		Title:     "SPOOFING",
		ElementID: "malicious-js",
	})
	d.AddThreat(stride.Threat{
		Type:      stride.ElevationOfPrivilege,
		Title:     "ELEVATION",
		ElementID: "gateway",
	})
	d.AddThreat(stride.Threat{
		Type:      stride.InformationDisclosure,
		Title:     "INFO DISCLOSURE",
		ElementID: "config",
	})

	// Render to D2
	renderer := diagram.NewRenderer()
	renderer.IncludeComments = true
	output := renderer.Render(d)

	fmt.Print(output)
}
