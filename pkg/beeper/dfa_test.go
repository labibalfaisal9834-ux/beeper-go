package beeper

import (
	"testing"
)

type dummyAction struct {
	id int
}

func matchesInput[A comparable](dfa *DFA[A], from StateId, input []byte) bool {
	state := from
	for _, b := range input {
		edge, ok := dfa.GetEdge(state, Input(b))
		if !ok {
			edge, ok = dfa.GetEdge(state, AnyInput)
			if !ok {
				return false
			}
		}
		state = edge.To
	}
	return true
}

func dfaWithOptionalInput(repeatable bool) *DFA[struct{}] {
	dfa := NewDFA[struct{}]()
	dfa.StartPattern(InitState).
		PushCI("aaa").
		PushOptional("b", repeatable).
		PushCI("c")
	return dfa
}

func TestNonRepeatableOptionalInputCannotBeRepeated(t *testing.T) {
	dfa := dfaWithOptionalInput(false)
	if !matchesInput(dfa, InitState, []byte("aaa")) {
		t.Errorf("expected aaa to match")
	}
	if !matchesInput(dfa, InitState, []byte("aaab")) {
		t.Errorf("expected aaab to match")
	}
	if !matchesInput(dfa, InitState, []byte("aaabc")) {
		t.Errorf("expected aaabc to match")
	}
	if matchesInput(dfa, InitState, []byte("aaabbc")) {
		t.Errorf("expected aaabbc NOT to match")
	}
}

func TestRepeatableOptionalInputCanBeRepeated(t *testing.T) {
	dfa := dfaWithOptionalInput(true)
	if !matchesInput(dfa, InitState, []byte("aaa")) {
		t.Errorf("expected aaa to match")
	}
	if !matchesInput(dfa, InitState, []byte("aaab")) {
		t.Errorf("expected aaab to match")
	}
	if !matchesInput(dfa, InitState, []byte("aaabc")) {
		t.Errorf("expected aaabc to match")
	}
	if !matchesInput(dfa, InitState, []byte("aaabbc")) {
		t.Errorf("expected aaabbc to match")
	}
}

func TestOptionalInputIsOptional(t *testing.T) {
	dfa1 := dfaWithOptionalInput(true)
	if !matchesInput(dfa1, InitState, []byte("aaa")) {
		t.Errorf("expected aaa to match")
	}
	if !matchesInput(dfa1, InitState, []byte("aaac")) {
		t.Errorf("expected aaac to match")
	}

	dfa2 := dfaWithOptionalInput(false)
	if !matchesInput(dfa2, InitState, []byte("aaa")) {
		t.Errorf("expected aaa to match")
	}
	if !matchesInput(dfa2, InitState, []byte("aaac")) {
		t.Errorf("expected aaac to match")
	}
}

func TestPushOptionsCI(t *testing.T) {
	dfa := NewDFA[dummyAction]()
	dfa.StartPattern(InitState).
		PushOptionsCI([]string{"GET", "POST", "DELETE"}).
		With(dummyAction{id: 42})

	methods := []string{"get", "GET", "post", "POST", "delete", "DELETE", "DeLeTe"}
	for _, m := range methods {
		if !matchesInput(dfa, InitState, []byte(m)) {
			t.Errorf("expected method %q to match", m)
		}
	}

	if matchesInput(dfa, InitState, []byte("PUT")) {
		t.Errorf("expected PUT NOT to match")
	}
}

func TestPushAnyBoundedAndUnbounded(t *testing.T) {
	// Bounded [3..3]
	dfa := NewDFA[dummyAction]()
	dfa.StartPattern(InitState).
		Push("CODE:").
		PushAny(3, 3).
		Push("\r\n")

	if !matchesInput(dfa, InitState, []byte("CODE:200\r\n")) {
		t.Errorf("expected CODE:200\\r\\n to match")
	}
	if matchesInput(dfa, InitState, []byte("CODE:20\r\n")) {
		t.Errorf("expected CODE:20\\r\\n NOT to match")
	}
	if matchesInput(dfa, InitState, []byte("CODE:2000\r\n")) {
		t.Errorf("expected CODE:2000\\r\\n NOT to match")
	}
}

func TestRestartWith(t *testing.T) {
	dfa := NewDFA[dummyAction]()
	dfa.StartPattern(InitState).
		Push("HTTP/1.1").
		RestartWith("\n")

	if !matchesInput(dfa, InitState, []byte("HTTP/1.1\n")) {
		t.Errorf("expected restart with \\n to match")
	}
}

func TestEdgeActionConflicts(t *testing.T) {
	dfa := NewDFA[int]()
	act1 := 10
	act2 := 20
	dfa.InsertEdge(InitState, Input('a'), 2, &act1)

	// Inserting same action is OK
	dfa.InsertEdge(InitState, Input('a'), 2, &act1)

	// Inserting conflicting action must panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on conflicting action")
		}
	}()
	dfa.InsertEdge(InitState, Input('a'), 2, &act2)
}
