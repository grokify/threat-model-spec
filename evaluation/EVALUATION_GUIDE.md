# Vulnerability Documentation Evaluation Guide

This guide provides evaluation criteria for assessing vulnerability articles, threat models, and diagrams for publication readiness on a leading security company's blog.

## Rubric Format

Rubrics are defined in **JSON format** optimized for LLM-as-Judge evaluation:

```
evaluation/
├── schema/
│   └── rubric.schema.json          # JSON Schema for rubric validation
├── rubrics/
│   └── vulnerability-article.rubric.json  # Article evaluation rubric
├── *.go                            # Go types (for programmatic use)
└── EVALUATION_GUIDE.md             # This guide
```

### Why JSON for Rubrics?

Based on research into LLM-as-Judge best practices ([G-Eval](https://arxiv.org/abs/2303.16634), [Prometheus](https://arxiv.org/abs/2310.08491)):

| Feature | JSON Rubrics | Go Code |
|---------|--------------|---------|
| LLM can read directly | Yes | No |
| Language-agnostic | Yes | No |
| Edit without recompiling | Yes | No |
| Schema-validated | Yes | Yes |
| Human + machine readable | Yes | Partial |

### Key Design Decisions

1. **Categorical scales (pass/partial/fail)** instead of 1-10 numeric - LLMs aren't calibrated for high-precision scoring
2. **Few-shot examples** in each category - research shows 1 example improves alignment
3. **Chain-of-thought prompting** - require reasoning before score
4. **Structured JSON output** - enables automated processing

## Quick Reference: Pass Criteria

### Publication Standard (Default)

| Metric | Threshold |
|--------|-----------|
| Minimum Weighted Score | 7.5 |
| Critical Findings | 0 allowed |
| High Findings | 0 allowed |
| Medium Findings | ≤3 allowed |
| Required Category Min | 7.0 |

### Flagship Publication (Strict)

| Metric | Threshold |
|--------|-----------|
| Minimum Weighted Score | 8.5 |
| Critical Findings | 0 allowed |
| High Findings | 0 allowed |
| Medium Findings | ≤1 allowed |
| Required Category Min | 8.0 |

---

## Part 1: Vulnerability Article Evaluation

### Category Weights

| Category | Weight | Required | Description |
|----------|--------|----------|-------------|
| Technical Accuracy | 2.0 | Yes | Correctness of CVE data, code patterns, attack mechanics |
| Responsible Disclosure | 1.5 | Yes | Ethical disclosure practices |
| Completeness | 1.5 | Yes | Coverage of all essential sections |
| Actionability | 1.5 | Yes | Usefulness of mitigations and detection |
| Framework Mappings | 1.0 | Yes | Accuracy of ATT&CK, CWE, OWASP mappings |
| Source Attribution | 1.0 | Yes | Proper credits and references |
| Detection Content | 1.0 | No | Quality of IOCs, Sigma rules, queries |
| Writing Quality | 0.75 | Yes | Clarity, tone, professionalism |
| Diagram Quality | 0.75 | No | Clarity and accuracy of visuals |

### Scoring Scale

| Score | Label | Description |
|-------|-------|-------------|
| 9-10 | Excellent | Exceeds expectations, publication ready |
| 7-8.9 | Good | Meets expectations, minor improvements possible |
| 5-6.9 | Adequate | Acceptable but needs improvement |
| 3-4.9 | Poor | Below expectations, significant issues |
| 0-2.9 | Unacceptable | Fails requirements, major rework needed |

### Category Details

#### Technical Accuracy (Weight: 2.0) ⭐ CRITICAL

**What to evaluate:**

- CVE ID, CVSS score, affected versions match NVD
- Code patterns are syntactically correct
- Attack chain is technically feasible
- Root cause analysis is accurate

**Scoring anchors:**

- **9-10**: All details verified against authoritative sources. Code compiles/runs. Attack chain tested or validated by SME.
- **7-8.9**: Details accurate with minor imprecisions. Code is correct.
- **5-6.9**: Core details correct, secondary details unverified.
- **3-4.9**: Multiple inaccuracies that could mislead.
- **0-2.9**: Fundamental errors. CVE details wrong.

#### Responsible Disclosure (Weight: 1.5) ⭐ CRITICAL

**What to evaluate:**

- Published after patch availability
- Disclosure timeline documented
- No unnecessary weaponization
- Authorization warnings present

**Scoring anchors:**

- **9-10**: Clear timeline. Published responsibly. Defensive focus.
- **7-8.9**: Timeline present. Appropriate detail level.
- **5-6.9**: Timing appears responsible but timeline incomplete.
- **3-4.9**: Unclear if coordinated. Excessive exploit detail.
- **0-2.9**: Premature disclosure. Weaponized content.

#### Completeness (Weight: 1.5)

**Required sections:**

- [ ] Overview
- [ ] TL;DR
- [ ] Affected Systems
- [ ] Technical Analysis (root cause, code patterns)
- [ ] Mitigations

**Recommended sections:**

- [ ] Immediate Actions
- [ ] Attack Chain Analysis
- [ ] Framework Mappings (ATT&CK, CWE, OWASP)
- [ ] Detection (IOCs, rules)
- [ ] Disclosure Timeline
- [ ] Tools & Resources

#### Actionability (Weight: 1.5)

**Checklist:**

- [ ] Immediate actions are prioritized
- [ ] Detection rules are copy-paste ready
- [ ] Mitigations have timeframes (immediate/short/long)
- [ ] Version check commands provided
- [ ] Workarounds for those who can't patch

#### Framework Mappings (Weight: 1.0)

**Verification checklist:**

- [ ] MITRE ATT&CK techniques match observable behaviors
- [ ] CWEs identify root cause (not just symptoms)
- [ ] OWASP categories are relevant (API/Web/LLM/Agentic)
- [ ] STRIDE analysis covers applicable categories

---

## Part 2: Threat Model JSON Evaluation

### Category Weights

| Category | Weight | Required | Description |
|----------|--------|----------|-------------|
| Attack Modeling | 1.5 | Yes | Quality of attack chain, tree, sequence |
| Schema Compliance | 1.5 | Yes | Valid JSON against schema |
| Mapping Accuracy | 1.25 | Yes | CVE, CWE, MITRE accuracy |
| Threat Coverage | 1.25 | Yes | Actors, scenarios, risk scoring |
| Mitigation Quality | 1.0 | Yes | Completeness and tracking |
| Asset Identification | 1.0 | Yes | Assets with classification |
| Credential Flows | 1.0 | No | Token/credential lifecycle |
| Red/Blue Content | 1.0 | No | Operational guidance |
| Diagram Integration | 0.75 | No | Embedded diagram quality |

### Validation Checklist

#### Schema Compliance

```bash
# Validate against schema
jsonschema -i threat-model.json schema/threat-model.schema.json
```

- [ ] No validation errors
- [ ] All required fields present
- [ ] Consistent ID format (e.g., `asset-*`, `threat-*`, `mit-*`)
- [ ] Valid enum values

#### Attack Modeling

- [ ] Attack chain has all steps documented
- [ ] Each step has MITRE tactic/technique
- [ ] Prerequisites specified
- [ ] Outcomes documented
- [ ] Attack tree includes probabilities (optional)
- [ ] Countermeasures linked

#### Mappings

- [ ] CVE ID exists in NVD
- [ ] CVSS vector parses correctly
- [ ] CWEs match root cause
- [ ] MITRE techniques are current (not deprecated)

---

## Part 3: Diagram Evaluation

### Category Weights

| Category | Weight | Required | Description |
|----------|--------|----------|-------------|
| Trust Boundaries | 1.5 | Yes | Clear boundary marking |
| Attack Flow Clarity | 1.5 | Yes | Clear attack sequence |
| Notation Standards | 1.25 | Yes | DFD, UML, attack tree conventions |
| Data Flow Accuracy | 1.25 | Yes | Correct protocols, directions |
| Consistency | 1.0 | Yes | Matches article/threat model |
| Rendering Quality | 0.75 | No | Clean layout, no overlaps |
| Accessibility | 0.5 | No | Color contrast, text labels |

### Diagram Type Requirements

#### Data Flow Diagram (DFD)

- [ ] Processes = circles/rounded rectangles
- [ ] External entities = rectangles
- [ ] Data stores = parallel lines
- [ ] Data flows = labeled arrows
- [ ] Trust boundaries = dashed lines

#### Sequence Diagram

- [ ] Actors/participants at top
- [ ] Time flows downward
- [ ] Messages labeled with action
- [ ] Return messages shown (if applicable)
- [ ] Activation boxes for processing

#### Attack Tree

- [ ] Root = goal node
- [ ] AND/OR gates clearly marked
- [ ] Leaf nodes = atomic actions
- [ ] Optional: probability annotations
- [ ] Optional: countermeasure links

#### Attack Chain/Flow

- [ ] Steps numbered chronologically
- [ ] MITRE techniques annotated
- [ ] Attack flows visually distinct from normal
- [ ] Outcomes at each step

---

## Part 4: Common Findings Reference

### Critical Findings (Publication Blockers)

| ID | Title | Category |
|----|-------|----------|
| ART-C001 | CVE details do not match NVD | Technical Accuracy |
| ART-C002 | Attack chain is technically implausible | Technical Accuracy |
| ART-C003 | Premature disclosure before patch | Responsible Disclosure |
| ART-C004 | Contains weaponized exploit code | Responsible Disclosure |
| ART-C005 | Potential plagiarism detected | Source Attribution |
| TM-C001 | Schema validation failure | Schema Compliance |
| TM-C002 | CVE ID is invalid or does not exist | Mapping Accuracy |

### High Findings (Must Fix)

| ID | Title | Category |
|----|-------|----------|
| ART-H001 | Code examples contain syntax errors | Technical Accuracy |
| ART-H002 | MITRE ATT&CK techniques incorrectly mapped | Framework Mappings |
| ART-H003 | Missing required section: Mitigations | Completeness |
| ART-H004 | Missing required section: Affected Systems | Completeness |
| ART-H005 | No actionable detection guidance | Actionability |
| TM-H001 | Attack chain missing MITRE mappings | Attack Modeling |
| TM-H002 | No assets defined | Asset Identification |
| DIA-H001 | Trust boundaries not marked | Trust Boundaries |
| DIA-H002 | Attack steps not numbered | Attack Flow Clarity |
| DIA-H003 | Diagram contradicts article | Consistency |

### Medium Findings (Should Fix)

| ID | Title | Category |
|----|-------|----------|
| ART-M001 | Missing relevant CWE mapping | Framework Mappings |
| ART-M002 | Detection rules not tested | Detection Content |
| ART-M003 | Diagrams use non-standard notation | Diagram Quality |
| ART-M004 | Original researchers not credited | Source Attribution |
| ART-M005 | Sensationalist language | Writing Quality |
| ART-M006 | Mitigations lack timeframes | Actionability |

---

## Part 5: Evaluation Workflow

### Pre-Evaluation Setup

1. Gather all artifacts:
   - Vulnerability article (markdown)
   - Threat model JSON
   - Diagram source files (Mermaid, D2)
   - Rendered diagrams (if applicable)

2. Verify sources:
   - Pull CVE from NVD
   - Locate vendor advisory
   - Find original researcher disclosure

### Evaluation Process

1. **Schema Validation** (Threat Model)
   - Run JSON schema validator
   - Document any validation errors

2. **Technical Review** (All)
   - Verify CVE details against NVD
   - Check code examples for syntax
   - Validate attack chain logic
   - Verify framework mappings

3. **Content Review** (Article)
   - Check all required sections present
   - Evaluate actionability of guidance
   - Review writing quality and tone

4. **Visual Review** (Diagrams)
   - Check notation standards
   - Verify trust boundaries marked
   - Confirm consistency with text

5. **Ethical Review** (All)
   - Verify disclosure timeline
   - Check for weaponized content
   - Confirm proper attribution

### Scoring

1. Score each category (0-10)
2. Apply category weights
3. Calculate weighted average
4. Count findings by severity
5. Apply pass criteria
6. Generate decision: PASS / CONDITIONAL / FAIL / HUMAN_REVIEW

### Decision Matrix

| Condition | Decision |
|-----------|----------|
| Critical or High findings present | FAIL |
| Score below minimum | HUMAN_REVIEW |
| Medium findings exceed limit | CONDITIONAL |
| All criteria met | PASS |

---

## Appendix: Integration with structured-evaluation

This rubric is designed to integrate with the [structured-evaluation](https://github.com/plexusone/structured-evaluation) framework.

### Creating an Evaluation Report

```go
import (
    "github.com/plexusone/structured-evaluation/evaluation"
    tmseval "github.com/grokify/threat-model-spec/evaluation"
)

// Create report
report := evaluation.NewEvaluationReport("vulnerability-article", "CVE-2026-25253")

// Add category scores
for _, rubric := range tmseval.VulnerabilityArticleRubricSet() {
    report.AddCategory(evaluation.CategoryScore{
        Category:      string(rubric.Category),
        Score:         8.5, // Evaluated score
        MaxScore:      10.0,
        Weight:        rubric.Weight,
        Justification: "...",
    })
}

// Add findings
report.AddFinding(evaluation.Finding{
    ID:             "ART-M001",
    Category:       "framework_mappings",
    Severity:       "medium",
    Title:          "Missing relevant CWE mapping",
    Description:    "Article does not map to CWE-346 (Origin Validation Error)",
    Recommendation: "Add CWE-346 to CWE Mappings section",
})

// Finalize with pass criteria
report.Finalize("sevaluation check report.json")
```

### CLI Usage

```bash
# Validate report structure
sevaluation validate evaluation-report.json

# Check pass/fail
sevaluation check evaluation-report.json

# Render detailed output
sevaluation render evaluation-report.json --format=detailed
```
