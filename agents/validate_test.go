// Package agents_test validates the agnostic multi-agent-spec definitions
// in agents/specs/ against the IR: every per-stage agent and slash command
// must exist for all six PDLC stages, parse as valid frontmatter, and
// reference a rubric and report profile that actually resolve. This is the
// "definition-validation tests (contracts parse, rubric/artifact refs
// resolve)" deliverable from TPD Phase 3 item 4 (RMI-THREATMODELSPEC-110).
package agents_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/grokify/threat-model-spec/evaluation"
	"github.com/grokify/threat-model-spec/ir"
)

// agentFrontmatter mirrors the fields multi-agent-spec agent definitions
// use in agents/specs/agents/*.md.
type agentFrontmatter struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Model        string   `yaml:"model"`
	Tools        []string `yaml:"tools"`
	AllowedTools []string `yaml:"allowedTools"`
	Requires     []string `yaml:"requires"`
	Tasks        []struct {
		ID          string `yaml:"id"`
		Description string `yaml:"description"`
		Type        string `yaml:"type"`
		Command     string `yaml:"command"`
		Required    bool   `yaml:"required"`
	} `yaml:"tasks"`
}

// commandFrontmatter mirrors the fields multi-agent-spec command
// definitions use in agents/specs/commands/*.md.
type commandFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Arguments   []struct {
		Name        string `yaml:"name"`
		Type        string `yaml:"type"`
		Required    bool   `yaml:"required"`
		Default     string `yaml:"default"`
		Description string `yaml:"description"`
	} `yaml:"arguments"`
	Dependencies []string `yaml:"dependencies"`
	Process      []string `yaml:"process"`
}

// splitFrontmatter separates the leading "---\n...\n---\n" YAML block from
// the Markdown body that follows it.
func splitFrontmatter(t *testing.T, path string) (frontmatter, body string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	content := string(data)
	if !strings.HasPrefix(content, "---\n") {
		t.Fatalf("%s: does not start with a YAML frontmatter block", path)
	}
	rest := content[len("---\n"):]
	idx := strings.Index(rest, "\n---\n")
	if idx == -1 {
		t.Fatalf("%s: unterminated frontmatter block", path)
	}
	return rest[:idx], rest[idx+len("\n---\n"):]
}

func agentSpecPath(stage ir.Stage) string {
	return filepath.Join("specs", "agents", fmt.Sprintf("%s-analyst.md", stage))
}

func commandSpecPath(stage ir.Stage) string {
	return filepath.Join("specs", "commands", fmt.Sprintf("analyze-%s.md", stage))
}

func TestEveryStageHasAnAgentDefinition(t *testing.T) {
	for _, stage := range ir.AllStages() {
		t.Run(string(stage), func(t *testing.T) {
			path := agentSpecPath(stage)
			fm, body := splitFrontmatter(t, path)

			var agent agentFrontmatter
			if err := yaml.Unmarshal([]byte(fm), &agent); err != nil {
				t.Fatalf("%s: frontmatter does not parse as YAML: %v", path, err)
			}

			wantName := fmt.Sprintf("%s-analyst", stage)
			if agent.Name != wantName {
				t.Errorf("name = %q, want %q", agent.Name, wantName)
			}
			if agent.Description == "" {
				t.Error("description is empty")
			}
			found := false
			for _, r := range agent.Requires {
				if r == "tms" {
					found = true
				}
			}
			if !found {
				t.Errorf("requires = %v, want it to include %q", agent.Requires, "tms")
			}
			if len(agent.Tasks) == 0 {
				t.Error("no tasks defined")
			}
			for _, task := range agent.Tasks {
				if task.Command == "" {
					t.Errorf("task %q has an empty command", task.ID)
				}
				if !strings.Contains(task.Command, string(stage)) {
					t.Errorf("task %q command %q does not reference stage %q", task.ID, task.Command, stage)
				}
			}

			if !strings.Contains(body, "## Output-Object Contract") {
				t.Error("body is missing a '## Output-Object Contract' section")
			}
			if !strings.Contains(body, "## Rubric Reference") {
				t.Error("body is missing a '## Rubric Reference' section")
			}
			if !strings.Contains(body, "## Worked Example") {
				t.Error("body is missing a '## Worked Example' section")
			}
			if !strings.Contains(strings.ToLower(body), "adversarial critic") {
				t.Error("body does not describe an adversarial-critic step")
			}
		})
	}
}

func TestEveryStageHasACommandDefinition(t *testing.T) {
	for _, stage := range ir.AllStages() {
		t.Run(string(stage), func(t *testing.T) {
			path := commandSpecPath(stage)
			fm, _ := splitFrontmatter(t, path)

			var cmd commandFrontmatter
			if err := yaml.Unmarshal([]byte(fm), &cmd); err != nil {
				t.Fatalf("%s: frontmatter does not parse as YAML: %v", path, err)
			}

			wantName := fmt.Sprintf("analyze-%s", stage)
			if cmd.Name != wantName {
				t.Errorf("name = %q, want %q", cmd.Name, wantName)
			}
			if cmd.Description == "" {
				t.Error("description is empty")
			}
			found := false
			for _, d := range cmd.Dependencies {
				if d == "tms" {
					found = true
				}
			}
			if !found {
				t.Errorf("dependencies = %v, want it to include %q", cmd.Dependencies, "tms")
			}
			if len(cmd.Process) == 0 {
				t.Error("no process steps defined")
			}
		})
	}
}

// TestAgentRubricReferencesResolve confirms the rubric ID mentioned in each
// agent's "## Rubric Reference" section is the real embedded stage rubric,
// not a stale or mistyped reference.
func TestAgentRubricReferencesResolve(t *testing.T) {
	for _, stage := range ir.AllStages() {
		t.Run(string(stage), func(t *testing.T) {
			rubric, err := evaluation.StageRubric(stage)
			if err != nil {
				t.Fatalf("evaluation.StageRubric(%q): %v", stage, err)
			}
			if len(rubric.Categories) == 0 {
				t.Fatalf("stage rubric for %q has no categories", stage)
			}

			_, body := splitFrontmatter(t, agentSpecPath(stage))
			if !strings.Contains(body, rubric.ID) {
				t.Errorf("agent body does not mention rubric ID %q", rubric.ID)
			}
			for _, cat := range rubric.Categories {
				if !strings.Contains(body, "`"+cat.ID+"`") {
					t.Errorf("agent body does not reference rubric category %q", cat.ID)
				}
			}
		})
	}
}

// TestAgentInputsMatchReportProfile confirms each agent's documented input
// mode and (for artifact-types stages) artifact types match the real
// embedded StageReportProfile, so a spec update to one can't silently drift
// from the other.
func TestAgentInputsMatchReportProfile(t *testing.T) {
	for _, stage := range ir.AllStages() {
		t.Run(string(stage), func(t *testing.T) {
			profile, err := ir.StageReportProfileByStage(stage)
			if err != nil {
				t.Fatalf("ir.StageReportProfileByStage(%q): %v", stage, err)
			}

			_, body := splitFrontmatter(t, agentSpecPath(stage))
			if !strings.Contains(body, "`"+string(profile.InputMode)+"`") {
				t.Errorf("agent body does not mention input mode %q", profile.InputMode)
			}
			for _, at := range profile.ArtifactTypes {
				if !strings.Contains(body, "`"+string(at)+"`") {
					t.Errorf("agent body does not mention artifact type %q", at)
				}
			}
			for _, id := range profile.ASPMDomainIDs {
				if !strings.Contains(body, "`"+string(id)+"`") {
					t.Errorf("agent body does not mention ASPM domain %q", id)
				}
			}
		})
	}
}

// TestDeploymentTargetsExist confirms the assistantkit deployment config
// (agents/specs/deployments/dist.json) references the spec directories
// that actually exist, so generation doesn't silently produce empty
// plugin output.
func TestDeploymentTargetsExist(t *testing.T) {
	for _, dir := range []string{"agents", "commands", "skills"} {
		path := filepath.Join("specs", dir)
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if len(entries) == 0 {
			t.Errorf("%s is empty", path)
		}
	}
}
