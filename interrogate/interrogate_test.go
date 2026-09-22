package interrogate_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Formulary-Labs/challenge/interrogate"
)

func makeArtifact(controls []interrogate.ControlEntry) *interrogate.ChallengeArtifact {
	return &interrogate.ChallengeArtifact{Controls: controls}
}

func TestRestatementTest(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{
			ID:             "A.5.1",
			Requirement:    "Policies for information security shall be defined and reviewed",
			Implementation: "Policies for information security are defined and reviewed by management",
		},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.RestatementTest) {
		t.Error("expected RESTATEMENT_TEST finding for near-identical implementation")
	}
}

func TestStakeholderAbsenceTest_noOwner(t *testing.T) {
	controls := make([]interrogate.ControlEntry, 10)
	for i := range controls {
		controls[i] = interrogate.ControlEntry{ID: fmt.Sprintf("A.%d", i+1)}
	}
	a := makeArtifact(controls)
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.StakeholderAbsenceTest) {
		t.Error("expected STAKEHOLDER_ABSENCE_TEST finding for controls with no owner")
	}
}

func TestEvidenceTraceabilityTest_missingFile(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{ID: "A.5.1", Determination: "satisfied", EvidencePath: "/nonexistent/path/evidence.pdf"},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.EvidenceTraceabilityTest) {
		t.Error("expected EVIDENCE_TRACEABILITY_TEST finding for missing evidence path")
	}
}

func TestExceptionHonestyTest_zeroExceptions(t *testing.T) {
	controls := make([]interrogate.ControlEntry, 15)
	for i := range controls {
		controls[i] = interrogate.ControlEntry{
			ID:            fmt.Sprintf("A.%d", i+1),
			Determination: "satisfied",
		}
	}
	a := makeArtifact(controls)
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.ExceptionHonestyTest) {
		t.Error("expected EXCEPTION_HONESTY_TEST for zero exceptions in a 15-control artifact")
	}
}

func TestCadenceSustainabilityTest_overdue(t *testing.T) {
	old := time.Now().Add(-200 * 24 * time.Hour)
	a := makeArtifact([]interrogate.ControlEntry{
		{ID: "A.5.1", ReviewCadenceDays: 90, LastReviewed: &old},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.CadenceSustainabilityTest) {
		t.Error("expected CADENCE_SUSTAINABILITY_TEST for overdue review")
	}
}

func TestInheritanceValidationTest(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{ID: "A.5.1", Inherited: true, InheritedFrom: "enterprise-isms"},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.InheritanceValidationTest) {
		t.Error("expected INHERITANCE_VALIDATION_TEST for inherited control without validated_for")
	}
}

func TestScopeBoundaryTest_unjustifiedExclusion(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{ID: "A.5.1", Excluded: true},
		{ID: "A.5.2", Excluded: true},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.ScopeBoundaryTest) {
		t.Error("expected SCOPE_BOUNDARY_TEST for excluded controls without justification")
	}
}

func TestOperationalRealityTest_passive(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{
			ID:             "A.5.1",
			Implementation: "Policies are documented. Access is reviewed. Training is performed. Incidents are managed. Records are maintained.",
		},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.OperationalRealityTest) {
		t.Error("expected OPERATIONAL_REALITY_TEST for highly passive implementation text")
	}
}

func TestLeadershipRealityTest(t *testing.T) {
	a := makeArtifact([]interrogate.ControlEntry{
		{ID: "A.5.1", LeadershipRequired: true, Owner: "management"},
	})
	r := interrogate.ApplyAll(a, "test.json", "low")
	if !hasPattern(r, interrogate.LeadershipRealityTest) {
		t.Error("expected LEADERSHIP_REALITY_TEST for generic owner on leadership control")
	}
}

func TestFromFile(t *testing.T) {
	artifact := &interrogate.ChallengeArtifact{
		Framework: "iso27001",
		Controls: []interrogate.ControlEntry{
			{ID: "A.5.1", Determination: "satisfied", Owner: "alice"},
		},
	}
	data, _ := json.Marshal(artifact)
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")
	os.WriteFile(path, data, 0o600) //nolint:errcheck

	loaded, err := interrogate.Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if loaded.Framework != "iso27001" {
		t.Errorf("framework = %q, want iso27001", loaded.Framework)
	}
}

func hasPattern(r interrogate.Report, id interrogate.PatternID) bool {
	for _, f := range r.Findings {
		if f.PatternID == id {
			return true
		}
	}
	return false
}
