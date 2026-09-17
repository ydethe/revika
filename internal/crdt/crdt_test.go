package crdt

import "testing"

func TestVectorClockRelations(t *testing.T) {
	base := Clock{"a": 1}
	if base.Compare(Clock{"a": 1, "b": 1}) != Before {
		t.Fatal("expected base clock to be before extended clock")
	}
	if (Clock{"a": 2}).Compare(Clock{"b": 1}) != Concurrent {
		t.Fatal("expected independent clocks to be concurrent")
	}
}

func TestTextConvergesForConcurrentInsertions(t *testing.T) {
	left := NewText()
	right := NewText()
	leftOps := left.Insert("alice", ElementID{}, "A")
	rightOps := right.Insert("bob", ElementID{}, "B")
	left.Merge(rightOps)
	right.Merge(leftOps)
	if left.String() != right.String() {
		t.Fatalf("replicas diverged: left=%q right=%q", left.String(), right.String())
	}
	if left.String() != "AB" {
		t.Fatalf("deterministic order = %q, want AB", left.String())
	}
}

func TestTextDeleteIsIdempotent(t *testing.T) {
	text := NewText()
	operations := text.Insert("alice", ElementID{}, "hello")
	id := *operations[1].Element
	deleteOperations := text.Delete(id.ID)
	text.Apply(deleteOperations[0])
	if text.String() != "hllo" {
		t.Fatalf("deleted text = %q, want hllo", text.String())
	}
}
