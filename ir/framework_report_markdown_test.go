package ir

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_AllFrameworks(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		STRIDE:      []STRIDEMapping{{Category: STRIDESpoofing, Name: "Spoofing", AffectedComponents: []string{"app"}}},
		LINDDUN:     []LINDDUNMapping{{Category: LINDDUNDisclosure, Name: "Disclosure"}},
		MITREAttack: []MITREAttackMapping{{TechniqueID: "T1059", TechniqueName: "Command Interpreter"}},
		OWASP:       []OWASPMapping{{Category: OWASPCategoryAPI, ID: "API2:2023", Name: "Broken Authentication"}},
	}

	wantHeader := map[FrameworkID]string{
		FrameworkSTRIDE:      "# STRIDE Report",
		FrameworkLINDDUN:     "# LINDDUN Report",
		FrameworkMITREAttack: "# MITRE ATT&CK Report",
		FrameworkOWASP:       "# OWASP Report",
		FrameworkAttackTree:  "# Attack Tree / Path Analysis Report",
	}

	for fw, header := range wantHeader {
		fw, header := fw, header
		t.Run(string(fw), func(t *testing.T) {
			report, err := ComputeFrameworkReport(tm, fw)
			if err != nil {
				t.Fatalf("ComputeFrameworkReport(%s): %v", fw, err)
			}
			md := report.RenderMarkdown()
			if !strings.HasPrefix(md, header) {
				t.Errorf("RenderMarkdown() = %q..., want prefix %q", md[:min(len(md), 40)], header)
			}
			if len(md) == 0 {
				t.Error("RenderMarkdown() is empty")
			}
		})
	}
}

func TestRenderMarkdown_UnknownFramework(t *testing.T) {
	report := &FrameworkReport{Framework: FrameworkID("not-a-real-framework")}
	md := report.RenderMarkdown()
	if !strings.Contains(md, "Unknown framework") {
		t.Errorf("RenderMarkdown() = %q, want it to mention the unknown framework", md)
	}
}

func TestRenderMarkdown_NilBodyIsGraceful(t *testing.T) {
	// A FrameworkReport with the Framework discriminator set but its typed
	// body left nil (e.g. hand-constructed, or a future framework not yet
	// wired into ComputeFrameworkReport) must not panic.
	report := &FrameworkReport{Framework: FrameworkSTRIDE}
	md := report.RenderMarkdown()
	if !strings.Contains(md, "No STRIDE body computed") {
		t.Errorf("RenderMarkdown() = %q, want a graceful nil-body message", md)
	}
}
