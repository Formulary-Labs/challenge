// Package interrogate implements the 10 deterministic interrogation patterns
// for challenge. Each pattern operates on a ChallengeArtifact — a structured
// representation of a compliance program artifact (SOA, control catalog,
// risk assessment, or assessment result).
//
// The patterns are structural and heuristic. They flag observations that a
// qualified SME should investigate; they do not substitute for SME judgment.
// All pattern implementations are deterministic given the same input.
//
// Pattern reference: functions/compliance-redteam-spec.md § Phase 3
package interrogate

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// PatternID is one of the 10 deterministic interrogation patterns.
type PatternID string

//nolint:revive // PatternID constants are self-documenting string identifiers.
const (
	RestatementTest           PatternID = "RESTATEMENT_TEST"
	StakeholderAbsenceTest    PatternID = "STAKEHOLDER_ABSENCE_TEST"
	EvidenceTraceabilityTest  PatternID = "EVIDENCE_TRACEABILITY_TEST"
	InheritanceValidationTest PatternID = "INHERITANCE_VALIDATION_TEST"
	ExceptionHonestyTest      PatternID = "EXCEPTION_HONESTY_TEST"
	CadenceSustainabilityTest PatternID = "CADENCE_SUSTAINABILITY_TEST"
	RiskAppetiteTest          PatternID = "RISK_APPETITE_TEST"
	LeadershipRealityTest     PatternID = "LEADERSHIP_REALITY_TEST"
	ScopeBoundaryTest         PatternID = "SCOPE_BOUNDARY_TEST"
	OperationalRealityTest    PatternID = "OPERATIONAL_REALITY_TEST"
)

// Severity mirrors the spec severity levels.
type Severity string

//nolint:revive // Severity constants are self-documenting.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

// Finding is a single triggered pattern result.
type Finding struct {
	ID             string    `json:"id"`
	PatternID      PatternID `json:"pattern_id"`
	Severity       Severity  `json:"severity"`
	ControlID      string    `json:"control_id,omitempty"`
	Observation    string    `json:"observation"`
	Risk           string    `json:"risk"`
	Recommendation string    `json:"recommendation"`
}

// Report is the full challenge output.
type Report struct {
	Artifact       string      `json:"artifact"`
	Framework      string      `json:"framework,omitempty"`
	GeneratedAt    time.Time   `json:"generated_at"`
	OverallPosture Severity    `json:"overall_posture"`
	Findings       []Finding   `json:"findings"`
	PatternsRun    []PatternID `json:"patterns_run"`
	Disclaimer     string      `json:"disclaimer"`
}

// ControlEntry represents a single control in the artifact.
type ControlEntry struct {
	ID                     string     `json:"id"`
	Title                  string     `json:"title,omitempty"`
	Requirement            string     `json:"requirement,omitempty"`
	Implementation         string     `json:"implementation,omitempty"`
	Owner                  string     `json:"owner,omitempty"`
	Inherited              bool       `json:"inherited,omitempty"`
	InheritedFrom          string     `json:"inherited_from,omitempty"`
	ValidatedFor           string     `json:"validated_for,omitempty"`
	EvidenceRef            string     `json:"evidence_ref,omitempty"`
	EvidencePath           string     `json:"evidence_path,omitempty"`
	Determination          string     `json:"determination,omitempty"` // satisfied, partially_satisfied, not_satisfied, na
	LastReviewed           *time.Time `json:"last_reviewed,omitempty"`
	ReviewCadenceDays      int        `json:"review_cadence_days,omitempty"`
	RiskScore              float64    `json:"risk_score,omitempty"` // 0-9 matrix score
	RiskAccepted           bool       `json:"risk_accepted,omitempty"`
	LeadershipRequired     bool       `json:"leadership_required,omitempty"`
	Excluded               bool       `json:"excluded,omitempty"`
	ExclusionJustification string     `json:"exclusion_justification,omitempty"`
}

// ChallengeArtifact is the top-level artifact structure challenge reads.
// It accepts gemara ControlCatalog shape and a richer SOA/assessment shape.
type ChallengeArtifact struct {
	Framework      string         `json:"framework,omitempty"`
	Program        string         `json:"program,omitempty"`
	ProductContext string         `json:"product_context,omitempty"`
	Scope          string         `json:"scope,omitempty"`
	ExclusionCount int            `json:"exclusion_count,omitempty"`
	ExceptionCount int            `json:"exception_count,omitempty"`
	Controls       []ControlEntry `json:"controls,omitempty"`

	// CatalogPath is an optional path to a gemara ControlCatalog YAML that
	// provides the canonical control list for inheritance validation. Set by
	// the caller via --catalog; not part of the artifact JSON itself.
	CatalogPath string `json:"-"`

	// gemara ControlCatalog shape compatibility.
	Metadata *struct {
		Type      string `json:"type,omitempty"`
		Framework string `json:"framework,omitempty"`
		Program   string `json:"program,omitempty"`
	} `json:"metadata,omitempty"`

	// Nested controls under groups (gemara shape).
	Groups []struct {
		ID       string         `json:"id,omitempty"`
		Controls []ControlEntry `json:"controls,omitempty"`
	} `json:"groups,omitempty"`
}

// allControls returns all controls from both flat and grouped shapes.
func (a *ChallengeArtifact) allControls() []ControlEntry {
	controls := a.Controls
	for _, g := range a.Groups {
		controls = append(controls, g.Controls...)
	}
	return controls
}

// Load reads and parses a challenge artifact from a file.
func Load(path string) (*ChallengeArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading artifact %q: %w", path, err)
	}
	var a ChallengeArtifact
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing artifact %q: %w", path, err)
	}
	// Normalize from gemara metadata.
	if a.Metadata != nil {
		if a.Framework == "" {
			a.Framework = a.Metadata.Framework
		}
		if a.Program == "" {
			a.Program = a.Metadata.Program
		}
	}
	return &a, nil
}

const disclaimer = "All findings require validation by a qualified compliance SME before action is taken."

// ApplyAll runs all 10 patterns and returns a Report.
// severityThreshold filters findings below the threshold (e.g. "medium" excludes low).
func ApplyAll(a *ChallengeArtifact, artifactPath, severityThreshold string) Report {
	r := Report{
		Artifact:    artifactPath,
		Framework:   a.Framework,
		GeneratedAt: time.Now().UTC(),
		Disclaimer:  disclaimer,
	}

	allPatterns := []PatternID{
		RestatementTest,
		StakeholderAbsenceTest,
		EvidenceTraceabilityTest,
		InheritanceValidationTest,
		ExceptionHonestyTest,
		CadenceSustainabilityTest,
		RiskAppetiteTest,
		LeadershipRealityTest,
		ScopeBoundaryTest,
		OperationalRealityTest,
	}
	r.PatternsRun = allPatterns

	var all []Finding
	all = append(all, applyRestatementTest(a)...)
	all = append(all, applyStakeholderAbsenceTest(a)...)
	all = append(all, applyEvidenceTraceabilityTest(a, filepath.Dir(artifactPath))...)
	all = append(all, applyInheritanceValidationTest(a)...)
	all = append(all, applyExceptionHonestyTest(a)...)
	all = append(all, applyCadenceSustainabilityTest(a)...)
	all = append(all, applyRiskAppetiteTest(a)...)
	all = append(all, applyLeadershipRealityTest(a)...)
	all = append(all, applyScopeBoundaryTest(a)...)
	all = append(all, applyOperationalRealityTest(a)...)

	// Assign sequential IDs.
	for i := range all {
		all[i].ID = fmt.Sprintf("RT-%03d", i+1)
	}

	// Filter by severity threshold.
	threshold := severityOrder(Severity(severityThreshold))
	for _, f := range all {
		if severityOrder(f.Severity) >= threshold {
			r.Findings = append(r.Findings, f)
		}
	}

	r.OverallPosture = computePosture(r.Findings)
	return r
}

func severityOrder(s Severity) int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

func computePosture(findings []Finding) Severity {
	worst := Low
	for _, f := range findings {
		if severityOrder(f.Severity) > severityOrder(worst) {
			worst = f.Severity
		}
	}
	if len(findings) == 0 {
		return Low
	}
	return worst
}

// --- Pattern implementations ---

// 1. Restatement Test: implementation text too similar to the requirement.
func applyRestatementTest(a *ChallengeArtifact) []Finding {
	var out []Finding
	for _, c := range a.allControls() {
		if c.Implementation == "" || c.Requirement == "" {
			continue
		}
		if textSimilarity(c.Requirement, c.Implementation) >= 0.65 {
			out = append(out, Finding{
				PatternID:      RestatementTest,
				Severity:       High,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s: implementation text is %.0f%% similar to the requirement — likely a restatement, not an implementation description", c.ID, textSimilarity(c.Requirement, c.Implementation)*100),
				Risk:           "Auditor will flag a restatement as non-conformant — the program cannot demonstrate what it actually does",
				Recommendation: "Replace with a concrete description of operational behavior: who does what, how often, and where the evidence lives",
			})
		}
	}
	return out
}

// 2. Stakeholder Absence Test: single owner across too many domains.
func applyStakeholderAbsenceTest(a *ChallengeArtifact) []Finding {
	ownerCounts := map[string]int{}
	total := 0
	for _, c := range a.allControls() {
		if c.Owner != "" {
			ownerCounts[c.Owner]++
		}
		total++
	}
	if total == 0 {
		return nil
	}
	var out []Finding
	for owner, count := range ownerCounts {
		pct := float64(count) / float64(total) * 100
		if pct >= 50 && total >= 5 {
			out = append(out, Finding{
				PatternID:      StakeholderAbsenceTest,
				Severity:       Medium,
				Observation:    fmt.Sprintf("Owner %q is assigned to %.0f%% of controls (%d/%d) — single point of ownership failure", owner, pct, count, total),
				Risk:           "Key person dependency; ownership gaps become visible under audit interview or personnel change",
				Recommendation: "Distribute control ownership; ensure each control domain has a distinct named owner who can speak to implementation",
			})
		}
	}
	// Flag controls with no owner.
	noOwner := 0
	for _, c := range a.allControls() {
		if c.Owner == "" && !c.Excluded {
			noOwner++
		}
	}
	if noOwner > 0 {
		out = append(out, Finding{
			PatternID:      StakeholderAbsenceTest,
			Severity:       High,
			Observation:    fmt.Sprintf("%d control(s) have no named owner — [OWNER NEEDED]", noOwner),
			Risk:           "Unowned controls are undefended in an audit interview",
			Recommendation: "Assign a named owner to every in-scope control before audit preparation",
		})
	}
	return out
}

// 3. Evidence Traceability Test: evidence_ref points to non-existent path.
func applyEvidenceTraceabilityTest(a *ChallengeArtifact, baseDir string) []Finding {
	var out []Finding
	noEvidence := 0
	for _, c := range a.allControls() {
		if c.Excluded || c.Determination == "na" {
			continue
		}
		// Check if evidencePath is a real file.
		if c.EvidencePath != "" {
			full := c.EvidencePath
			if !filepath.IsAbs(full) {
				full = filepath.Join(baseDir, c.EvidencePath)
			}
			if _, err := os.Stat(full); os.IsNotExist(err) {
				out = append(out, Finding{
					PatternID:      EvidenceTraceabilityTest,
					Severity:       High,
					ControlID:      c.ID,
					Observation:    fmt.Sprintf("Control %s: evidence_path %q does not exist — [CITATION NOT FOUND]", c.ID, c.EvidencePath),
					Risk:           "Referenced evidence cannot be produced under audit — conformance claim is unsupported",
					Recommendation: "Verify evidence path is correct and the file exists; update path or re-collect evidence",
				})
			}
		} else if c.EvidenceRef == "" && c.Determination == "satisfied" {
			noEvidence++
		}
	}
	if noEvidence > 0 {
		out = append(out, Finding{
			PatternID:      EvidenceTraceabilityTest,
			Severity:       High,
			Observation:    fmt.Sprintf("%d control(s) are marked satisfied with no evidence reference or path", noEvidence),
			Risk:           "Untraced conformance claims will not survive audit — satisfaction without evidence is assertion",
			Recommendation: "Add evidence_ref or evidence_path to every control marked satisfied or partially_satisfied",
		})
	}
	return out
}

// 4. Inheritance Validation Test: inherited controls not validated for this product.
func applyInheritanceValidationTest(a *ChallengeArtifact) []Finding {
	var out []Finding
	for _, c := range a.allControls() {
		if c.Inherited && c.ValidatedFor == "" {
			out = append(out, Finding{
				PatternID:      InheritanceValidationTest,
				Severity:       High,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s is marked inherited from %q with no validated_for field — inheritance without validation is assumption", c.ID, c.InheritedFrom),
				Risk:           "An auditor will ask how the enterprise control applies to this product's specific context and threat model",
				Recommendation: "Add validated_for field describing how this control was verified applicable to this product scope",
			})
		}
	}
	return out
}

// 5. Exception Honesty Test: zero exceptions in a non-trivial program.
func applyExceptionHonestyTest(a *ChallengeArtifact) []Finding {
	controls := a.allControls()
	if len(controls) < 10 {
		return nil // too small to apply
	}
	// Count excluded + not_satisfied + accepted risk with no exception documented.
	exceptions := a.ExceptionCount
	notSatisfied := 0
	for _, c := range controls {
		if c.Determination == "not_satisfied" {
			notSatisfied++
		}
	}
	if exceptions == 0 && notSatisfied == 0 && len(controls) >= 10 {
		return []Finding{{
			PatternID:      ExceptionHonestyTest,
			Severity:       Medium,
			Observation:    fmt.Sprintf("Artifact documents %d controls with zero exceptions and zero not-satisfied determinations — a program this clean has either not looked hard enough or has not documented exceptions honestly", len(controls)),
			Risk:           "Auditors treat a zero-exception program with suspicion; undisclosed exceptions become findings",
			Recommendation: "Review scope and control applicability; document genuine exceptions with justification and risk acceptance",
		}}
	}
	return nil
}

// 6. Cadence Sustainability Test: recurring controls not reviewed within cadence.
func applyCadenceSustainabilityTest(a *ChallengeArtifact) []Finding {
	now := time.Now()
	var out []Finding
	for _, c := range a.allControls() {
		if c.ReviewCadenceDays == 0 || c.LastReviewed == nil {
			continue
		}
		daysSince := int(now.Sub(*c.LastReviewed).Hours() / 24)
		if daysSince > c.ReviewCadenceDays {
			out = append(out, Finding{
				PatternID:      CadenceSustainabilityTest,
				Severity:       High,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s: last reviewed %d days ago, cadence is %d days — overdue by %d days", c.ID, daysSince, c.ReviewCadenceDays, daysSince-c.ReviewCadenceDays),
				Risk:           "Recurring requirement treated as a one-time event; cadence lapse is an audit finding",
				Recommendation: "Restore the review cadence; schedule the next review and add it to the evidence calendar (dose)",
			})
		}
	}
	return out
}

// 7. Risk Appetite Test: all risks cluster suspiciously low.
func applyRiskAppetiteTest(a *ChallengeArtifact) []Finding {
	controls := a.allControls()
	if len(controls) < 5 {
		return nil
	}
	scored := 0
	highRisk := 0
	for _, c := range controls {
		if c.RiskScore > 0 {
			scored++
			if c.RiskScore >= 6 { // 3x2 or 2x3 on 3x3 matrix
				highRisk++
			}
		}
	}
	if scored < 5 {
		return nil // not enough data
	}
	pctHigh := float64(highRisk) / float64(scored) * 100
	if pctHigh < 5 { // less than 5% of controls rated high/critical risk
		return []Finding{{
			PatternID:      RiskAppetiteTest,
			Severity:       Medium,
			Observation:    fmt.Sprintf("%.0f%% of scored controls have a risk score ≥ 6 (%d/%d) — risk decisions cluster suspiciously in the low range", pctHigh, highRisk, scored),
			Risk:           "A risk assessment designed to produce low scores rather than reflect operational reality will not survive a post-incident review",
			Recommendation: "Re-score risks using genuine threat modeling, not risk appetite as a ceiling; accept high residual risks explicitly rather than scoring them away",
		}}
	}
	return nil
}

// 8. Leadership Reality Test: leadership controls with generic or empty owners.
func applyLeadershipRealityTest(a *ChallengeArtifact) []Finding {
	genericOwners := map[string]bool{
		"management": true, "leadership": true, "executive": true, "senior management": true,
		"ciso": true, "ceo": true, "board": true, "committee": true,
	}
	var out []Finding
	for _, c := range a.allControls() {
		if !c.LeadershipRequired {
			continue
		}
		if c.Owner == "" {
			out = append(out, Finding{
				PatternID:      LeadershipRealityTest,
				Severity:       High,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s requires leadership but has no named owner — [OWNER NEEDED]", c.ID),
				Risk:           "Cannot demonstrate leadership commitment under audit interview",
				Recommendation: "Assign a named individual (not a role title) and document the last instance of leadership involvement",
			})
		} else if genericOwners[strings.ToLower(strings.TrimSpace(c.Owner))] {
			out = append(out, Finding{
				PatternID:      LeadershipRealityTest,
				Severity:       Medium,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s requires leadership; owner is %q — a role title, not a named individual", c.ID, c.Owner),
				Risk:           "Role titles do not survive interview-based audit; leadership accountability cannot be verified",
				Recommendation: "Replace role titles with named individuals; ensure the named person can speak to this control",
			})
		}
	}
	return out
}

// 9. Scope Boundary Test: exclusions without justification.
func applyScopeBoundaryTest(a *ChallengeArtifact) []Finding {
	unjustified := 0
	for _, c := range a.allControls() {
		if c.Excluded && c.ExclusionJustification == "" {
			unjustified++
		}
	}
	if unjustified == 0 {
		return nil
	}
	return []Finding{{
		PatternID:      ScopeBoundaryTest,
		Severity:       High,
		Observation:    fmt.Sprintf("%d control(s) are excluded from scope with no justification documented", unjustified),
		Risk:           "Auditor can challenge any exclusion; undocumented exclusions are automatically suspect",
		Recommendation: "Add exclusion_justification to every excluded control; describe why the control does not apply to this scope",
	}}
}

// 10. Operational Reality Test: passive voice / no named actors / performative language.
func applyOperationalRealityTest(a *ChallengeArtifact) []Finding {
	var out []Finding
	for _, c := range a.allControls() {
		if c.Implementation == "" {
			continue
		}
		score := passiveVoiceScore(c.Implementation)
		if score >= 0.4 { // 40%+ passive constructions
			out = append(out, Finding{
				PatternID:      OperationalRealityTest,
				Severity:       Low,
				ControlID:      c.ID,
				Observation:    fmt.Sprintf("Control %s: implementation text has %.0f%% passive constructions — reads like documentation written to satisfy a requirement, not a description of operational behavior", c.ID, score*100),
				Risk:           "Performative documentation is a medium-severity audit finding in management system standards",
				Recommendation: "Rewrite in active voice naming the actor: 'The [team/person] reviews [artifact] [cadence] and records results in [location]'",
			})
		}
	}
	return out
}

// --- text helpers ---

// textSimilarity returns word-level Jaccard similarity between two strings.
func textSimilarity(a, b string) float64 {
	aWords := wordSet(a)
	bWords := wordSet(b)
	if len(aWords) == 0 && len(bWords) == 0 {
		return 1.0
	}
	intersection := 0
	for w := range aWords {
		if bWords[w] {
			intersection++
		}
	}
	union := len(aWords) + len(bWords) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// wordSet normalises text and returns a set of lowercase words (stop words removed).
func wordSet(s string) map[string]bool {
	stop := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "of": true,
		"to": true, "in": true, "for": true, "is": true, "are": true, "be": true,
		"with": true, "that": true, "this": true, "it": true, "shall": true,
		"must": true, "should": true, "will": true, "by": true, "as": true,
		"at": true, "on": true, "all": true, "any": true, "from": true,
	}
	m := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(s)) {
		w = strings.TrimFunc(w, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		if w != "" && !stop[w] {
			m[w] = true
		}
	}
	return m
}

// passiveVoiceScore returns the fraction of sentences with passive voice markers.
func passiveVoiceScore(s string) float64 {
	passiveMarkers := []string{
		"is ", "are ", "was ", "were ", "be ", "been ", "being ",
		"is done", "are done", "is performed", "are performed", "is managed",
		"is maintained", "is reviewed", "is approved", "is documented",
	}
	sentences := strings.Split(s, ".")
	if len(sentences) == 0 {
		return 0
	}
	passive := 0
	for _, sent := range sentences {
		lower := strings.ToLower(sent)
		for _, m := range passiveMarkers {
			if strings.Contains(lower, m) {
				passive++
				break
			}
		}
	}
	return math.Min(float64(passive)/float64(len(sentences)), 1.0)
}
