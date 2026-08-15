package evaluation

import (
	"testing"

	"github.com/plexusone/structured-evaluation/claims"

	"github.com/grokify/threat-model-spec/ir"
)

func TestStageReviewType(t *testing.T) {
	for _, stage := range ir.AllStages() {
		got := StageReviewType(stage)
		if got != string(stage) {
			t.Errorf("StageReviewType(%q) = %q, want %q", stage, got, string(stage))
		}
	}
}

func TestFindingStatusToVerdict(t *testing.T) {
	tests := []struct {
		status ir.FindingStatus
		want   claims.Verdict
		wantOk bool
	}{
		{ir.FindingStatusValidated, claims.VerdictVerified, true},
		{ir.FindingStatusRejected, claims.VerdictRejected, true},
		{ir.FindingStatusInsufficientEvidence, claims.VerdictNeedsReview, true},
		{ir.FindingStatusCandidate, "", false},
	}
	for _, tt := range tests {
		got, ok := FindingStatusToVerdict(tt.status)
		if ok != tt.wantOk {
			t.Errorf("FindingStatusToVerdict(%q) ok = %v, want %v", tt.status, ok, tt.wantOk)
		}
		if got != tt.want {
			t.Errorf("FindingStatusToVerdict(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestVerdictToFindingStatus(t *testing.T) {
	tests := []struct {
		verdict claims.Verdict
		want    ir.FindingStatus
		wantOk  bool
	}{
		{claims.VerdictVerified, ir.FindingStatusValidated, true},
		{claims.VerdictRejected, ir.FindingStatusRejected, true},
		{claims.VerdictNeedsReview, ir.FindingStatusInsufficientEvidence, true},
		{claims.VerdictUnverified, "", false},
	}
	for _, tt := range tests {
		got, ok := VerdictToFindingStatus(tt.verdict)
		if ok != tt.wantOk {
			t.Errorf("VerdictToFindingStatus(%q) ok = %v, want %v", tt.verdict, ok, tt.wantOk)
		}
		if got != tt.want {
			t.Errorf("VerdictToFindingStatus(%q) = %q, want %q", tt.verdict, got, tt.want)
		}
	}
}

func TestFindingStatusVerdictRoundTrip(t *testing.T) {
	// The three statuses with a defined verdict must round-trip.
	statuses := []ir.FindingStatus{
		ir.FindingStatusValidated,
		ir.FindingStatusRejected,
		ir.FindingStatusInsufficientEvidence,
	}
	for _, s := range statuses {
		v, ok := FindingStatusToVerdict(s)
		if !ok {
			t.Fatalf("FindingStatusToVerdict(%q) unexpectedly not ok", s)
		}
		back, ok := VerdictToFindingStatus(v)
		if !ok {
			t.Fatalf("VerdictToFindingStatus(%q) unexpectedly not ok", v)
		}
		if back != s {
			t.Errorf("round-trip %q -> %q -> %q, want back to %q", s, v, back, s)
		}
	}
}
