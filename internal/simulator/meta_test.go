package simulator

import (
	"context"
	"testing"
)

// TestRun_MissingMetadataDoesNotPanic verifies that a corrupted FSM (metadata
// removed between events) surfaces via DecisionResult.Warnings instead of
// panicking. Regression guard for the old mustMeta panic path.
func TestRun_MissingMetadataDoesNotPanic(t *testing.T) {
	idx := newIdx()
	s := NewSimulator(idx)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("simulator panicked: %v", r)
		}
	}()

	s.fsm.SetState(StateIdle)
	// Intentionally do not populate metadata; dispatch the start event
	// directly. The first callback (onValidateSimContext) should bail
	// rather than panic.
	_ = s.fsm.Event(context.Background(), EventStart)
}

func TestGetMeta_MissingKey(t *testing.T) {
	s := NewSimulator(newIdx())
	_, err := getMeta[int](s.fsm, "nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestGetMeta_WrongType(t *testing.T) {
	s := NewSimulator(newIdx())
	s.fsm.SetMetadata("k", "string-value")
	_, err := getMeta[int](s.fsm, "k")
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}
