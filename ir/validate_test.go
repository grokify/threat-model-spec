package ir

import (
	"strings"
	"testing"
)

func TestValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		diagram DiagramIR
		wantErr string
	}{
		{
			name:    "empty diagram",
			diagram: DiagramIR{},
			wantErr: "type: required",
		},
		{
			name:    "missing title",
			diagram: DiagramIR{Type: DiagramTypeDFD},
			wantErr: "title: required",
		},
		{
			name:    "invalid type",
			diagram: DiagramIR{Type: "invalid", Title: "Test"},
			wantErr: "invalid type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidate_DFD(t *testing.T) {
	t.Run("valid DFD", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeDFD,
			Title: "Test DFD",
			Boundaries: []Boundary{
				{ID: "zone1", Label: "Zone 1", Type: BoundaryTypeLocalhost},
			},
			Elements: []Element{
				{ID: "proc1", Label: "Process 1", Type: ElementTypeProcess, ParentID: "zone1"},
				{ID: "store1", Label: "Store 1", Type: ElementTypeDatastore, ParentID: "zone1"},
			},
			Flows: []Flow{
				{From: "proc1", To: "store1", Label: "Write data"},
			},
		}
		if err := d.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("DFD requires elements", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeDFD,
			Title: "Test DFD",
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires at least one element") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("DFD should not have attacks", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeDFD,
			Title: "Test DFD",
			Elements: []Element{
				{ID: "proc1", Label: "Process 1", Type: ElementTypeProcess},
			},
			Attacks: []Attack{
				{Step: 1, From: "a", To: "b", Label: "Attack"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "should not have attacks") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("DFD invalid parent reference", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeDFD,
			Title: "Test DFD",
			Elements: []Element{
				{ID: "proc1", Label: "Process 1", Type: ElementTypeProcess, ParentID: "nonexistent"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unknown boundary") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidate_AttackChain(t *testing.T) {
	t.Run("valid attack chain", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeAttack,
			Title: "Test Attack",
			Elements: []Element{
				{ID: "attacker", Label: "Attacker", Type: ElementTypeExternalEntity},
				{ID: "victim", Label: "Victim", Type: ElementTypeProcess},
			},
			Attacks: []Attack{
				{Step: 1, From: "attacker", To: "victim", Label: "Attack step", MITRETactic: MITREInitialAccess},
			},
		}
		if err := d.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("attack chain requires attacks", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeAttack,
			Title: "Test Attack",
			Elements: []Element{
				{ID: "proc1", Label: "Process 1", Type: ElementTypeProcess},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires at least one attack") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("attack chain duplicate steps", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeAttack,
			Title: "Test Attack",
			Elements: []Element{
				{ID: "a", Label: "A", Type: ElementTypeProcess},
				{ID: "b", Label: "B", Type: ElementTypeProcess},
			},
			Attacks: []Attack{
				{Step: 1, From: "a", To: "b", Label: "Step 1"},
				{Step: 1, From: "b", To: "a", Label: "Step 1 duplicate"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "duplicate step") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("attack chain invalid target reference", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeAttack,
			Title: "Test Attack",
			Elements: []Element{
				{ID: "a", Label: "A", Type: ElementTypeProcess},
				{ID: "b", Label: "B", Type: ElementTypeProcess},
			},
			Attacks: []Attack{
				{Step: 1, From: "a", To: "b", Label: "Attack"},
			},
			Targets: []Target{
				{ElementID: "nonexistent", Classification: AssetClassificationHigh},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unknown element") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidate_Sequence(t *testing.T) {
	t.Run("valid sequence", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "client", Label: "Client"},
				{ID: "server", Label: "Server"},
			},
			Messages: []Message{
				{Seq: 1, From: "client", To: "server", Label: "Request"},
				{Seq: 2, From: "server", To: "client", Label: "Response"},
			},
		}
		if err := d.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence requires actors", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Messages: []Message{
				{Seq: 1, From: "a", To: "b", Label: "Msg"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires at least one actor") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence requires messages", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires at least one message") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence should not have elements", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
				{ID: "b", Label: "B"},
			},
			Messages: []Message{
				{Seq: 1, From: "a", To: "b", Label: "Msg"},
			},
			Elements: []Element{
				{ID: "proc", Label: "Process", Type: ElementTypeProcess},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "should not have elements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence invalid actor reference", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
			},
			Messages: []Message{
				{Seq: 1, From: "a", To: "nonexistent", Label: "Msg"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unknown actor") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence duplicate message seq", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
				{ID: "b", Label: "B"},
			},
			Messages: []Message{
				{Seq: 1, From: "a", To: "b", Label: "Msg 1"},
				{Seq: 1, From: "b", To: "a", Label: "Msg 1 duplicate"},
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "duplicate seq") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence valid phases", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
				{ID: "b", Label: "B"},
			},
			Messages: []Message{
				{Seq: 1, From: "a", To: "b", Label: "Msg 1"},
				{Seq: 2, From: "b", To: "a", Label: "Msg 2"},
				{Seq: 3, From: "a", To: "b", Label: "Msg 3"},
			},
			Phases: []Phase{
				{Name: "Phase 1", StartMessage: 1, EndMessage: 2},
				{Name: "Phase 2", StartMessage: 3, EndMessage: 3},
			},
		}
		if err := d.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sequence invalid phase range", func(t *testing.T) {
		d := &DiagramIR{
			Type:  DiagramTypeSequence,
			Title: "Test Sequence",
			Actors: []Actor{
				{ID: "a", Label: "A"},
				{ID: "b", Label: "B"},
			},
			Messages: []Message{
				{Seq: 1, From: "a", To: "b", Label: "Msg 1"},
			},
			Phases: []Phase{
				{Name: "Invalid", StartMessage: 1, EndMessage: 5}, // 5 doesn't exist
			},
		}
		err := d.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "outside message seq range") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidationErrors(t *testing.T) {
	t.Run("HasErrors", func(t *testing.T) {
		var errs ValidationErrors
		if errs.HasErrors() {
			t.Error("empty errors should not have errors")
		}
		errs = append(errs, ValidationError{Field: "test", Message: "error"})
		if !errs.HasErrors() {
			t.Error("non-empty errors should have errors")
		}
	})

	t.Run("Error string", func(t *testing.T) {
		errs := ValidationErrors{
			{Field: "field1", Message: "error1"},
			{Field: "field2", Message: "error2"},
		}
		errStr := errs.Error()
		if !strings.Contains(errStr, "2 validation error(s)") {
			t.Errorf("unexpected error string: %s", errStr)
		}
		if !strings.Contains(errStr, "field1: error1") {
			t.Errorf("missing field1 error: %s", errStr)
		}
		if !strings.Contains(errStr, "field2: error2") {
			t.Errorf("missing field2 error: %s", errStr)
		}
	})
}

func TestIsValid(t *testing.T) {
	valid := &DiagramIR{
		Type:  DiagramTypeDFD,
		Title: "Test",
		Elements: []Element{
			{ID: "a", Label: "A", Type: ElementTypeProcess},
		},
	}
	if !valid.IsValid() {
		t.Error("expected valid diagram to be valid")
	}

	invalid := &DiagramIR{}
	if invalid.IsValid() {
		t.Error("expected invalid diagram to be invalid")
	}
}

func TestMustValidate(t *testing.T) {
	t.Run("valid diagram", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("unexpected panic: %v", r)
			}
		}()
		d := &DiagramIR{
			Type:  DiagramTypeDFD,
			Title: "Test",
			Elements: []Element{
				{ID: "a", Label: "A", Type: ElementTypeProcess},
			},
		}
		d.MustValidate() // Should not panic
	})

	t.Run("invalid diagram panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid diagram")
			}
		}()
		d := &DiagramIR{}
		d.MustValidate() // Should panic
	})
}
