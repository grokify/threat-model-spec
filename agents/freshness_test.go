// Generation-freshness tests: fail if agents/plugins/ has drifted from
// agents/specs/ — the same discipline as the schema embed check, applied to
// assistantkit-generated plugin output (RMI-THREATMODELSPEC-111). These
// tests do not invoke the assistantkit binary (not a Go dependency); they
// check the deterministic parts of its output against the source specs.
package agents_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func specFileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("specs", dir))
	if err != nil {
		t.Fatalf("reading specs/%s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, strings.TrimSuffix(e.Name(), ".md"))
		}
	}
	if len(names) == 0 {
		t.Fatalf("no spec files found under specs/%s", dir)
	}
	return names
}

// TestClaudePluginAgentsAreFresh confirms every agent spec's Markdown body
// (everything after the frontmatter) is reproduced verbatim in the
// generated Claude plugin — the claude target passes agent bodies through
// unmodified, so any divergence means the plugin was generated from a
// stale spec (or hand-edited and never regenerated).
func TestClaudePluginAgentsAreFresh(t *testing.T) {
	for _, name := range specFileNames(t, "agents") {
		t.Run(name, func(t *testing.T) {
			_, specBody := splitFrontmatter(t, filepath.Join("specs", "agents", name+".md"))

			pluginPath := filepath.Join("plugins", "claude", "agents", name+".md")
			if _, err := os.Stat(pluginPath); err != nil {
				t.Fatalf("%s: not found — regenerate with `assistantkit generate --specs=agents/specs --target=dist --output=.`: %v", pluginPath, err)
			}
			_, pluginBody := splitFrontmatter(t, pluginPath)

			if pluginBody != specBody {
				t.Errorf("%s body differs from specs/agents/%s.md — stale, regenerate", pluginPath, name)
			}
		})
	}
}

// TestClaudePluginCommandsAreFresh confirms every process step declared in
// a command spec appears in the generated Claude command file. The claude
// command generator reformats structured frontmatter into prose (unlike
// agents, which pass through verbatim), so an exact body match isn't
// possible — but every process step's text is deterministically preserved,
// which is enough to catch a spec that was edited without regenerating.
func TestClaudePluginCommandsAreFresh(t *testing.T) {
	for _, name := range specFileNames(t, "commands") {
		t.Run(name, func(t *testing.T) {
			fm, _ := splitFrontmatter(t, filepath.Join("specs", "commands", name+".md"))
			var cmd commandFrontmatter
			if err := yaml.Unmarshal([]byte(fm), &cmd); err != nil {
				t.Fatalf("parsing command frontmatter: %v", err)
			}

			pluginPath := filepath.Join("plugins", "claude", "commands", name+".md")
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatalf("%s: not found — regenerate with `assistantkit generate --specs=agents/specs --target=dist --output=.`: %v", pluginPath, err)
			}
			content := string(data)

			for _, step := range cmd.Process {
				if !strings.Contains(content, step) {
					t.Errorf("%s is missing process step %q from specs/commands/%s.md — stale, regenerate", pluginPath, step, name)
				}
			}
		})
	}
}

// kiroAgent mirrors the fields assistantkit's kiro target writes per agent.
type kiroAgent struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Prompt      string `json:"prompt"`
}

// TestKiroPluginAgentsAreFresh confirms every agent spec has a
// corresponding kiro agent JSON file with a matching name/description and
// a prompt that still contains the spec's current Role section — catching
// the case where a spec's Role was rewritten but kiro's plugin wasn't
// regenerated.
func TestKiroPluginAgentsAreFresh(t *testing.T) {
	for _, name := range specFileNames(t, "agents") {
		t.Run(name, func(t *testing.T) {
			fm, specBody := splitFrontmatter(t, filepath.Join("specs", "agents", name+".md"))
			var agent agentFrontmatter
			if err := yaml.Unmarshal([]byte(fm), &agent); err != nil {
				t.Fatalf("parsing agent frontmatter: %v", err)
			}

			pluginPath := filepath.Join("plugins", "kiro", "agents", name+".json")
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatalf("%s: not found — regenerate with `assistantkit generate --specs=agents/specs --target=dist --output=.`: %v", pluginPath, err)
			}
			var ka kiroAgent
			if err := json.Unmarshal(data, &ka); err != nil {
				t.Fatalf("%s: invalid JSON: %v", pluginPath, err)
			}

			if ka.Name != agent.Name {
				t.Errorf("%s name = %q, want %q", pluginPath, ka.Name, agent.Name)
			}
			if ka.Description != agent.Description {
				t.Errorf("%s description = %q, want %q", pluginPath, ka.Description, agent.Description)
			}
			if !strings.Contains(ka.Prompt, strings.TrimSpace(specBody)) {
				t.Errorf("%s prompt does not contain the current spec body — stale, regenerate", pluginPath)
			}
		})
	}
}

// TestGeminiPluginCommandsExist confirms every command spec has a
// corresponding non-empty gemini command file. gemini output is TOML,
// which this repo has no parser dependency for, so this is an
// existence-and-non-triviality check rather than a content diff — enough
// to catch a spec added (or renamed) without regenerating.
func TestGeminiPluginCommandsExist(t *testing.T) {
	for _, name := range specFileNames(t, "commands") {
		t.Run(name, func(t *testing.T) {
			pluginPath := filepath.Join("plugins", "gemini", "commands", name+".toml")
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatalf("%s: not found — regenerate with `assistantkit generate --specs=agents/specs --target=dist --output=.`: %v", pluginPath, err)
			}
			if len(data) == 0 {
				t.Errorf("%s is empty", pluginPath)
			}
			if !strings.Contains(string(data), name) {
				t.Errorf("%s does not mention its own command name %q", pluginPath, name)
			}
		})
	}
}

// TestNoStaleFlatSkillFiles guards against a specific regression already
// hit once in this repo: an older assistantkit version generated skills as
// flat agents/plugins/claude/skills/<name>.md files; the current version
// generates agents/plugins/claude/skills/<name>/SKILL.md subdirectories
// instead but does not clean up the old flat files on regeneration, so
// they silently linger as stale duplicates unless removed by hand.
func TestNoStaleFlatSkillFiles(t *testing.T) {
	dir := filepath.Join("plugins", "claude", "skills")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			t.Errorf("%s is a stale flat skill file — current assistantkit generates skills/<name>/SKILL.md instead; remove it", filepath.Join(dir, e.Name()))
		}
	}
}
