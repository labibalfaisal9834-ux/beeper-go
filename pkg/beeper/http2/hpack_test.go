package http2

import (
	"bytes"
	"testing"

	"github.com/lerboe/beeper-go/pkg/beeper"
)

func representationStates() []beeper.StateId {
	var states []beeper.StateId
	for s := uint16(SField); s < SReserved; s++ {
		st := beeper.StateId(s)
		if st != SName {
			states = append(states, st)
		}
	}
	return states
}

func TestEveryRepresentationStateReadsEveryByte(t *testing.T) {
	dfa := DFA()

	for _, state := range representationStates() {
		inputs := make(map[beeper.Input]bool)
		for _, tr := range dfa.IterTransitions() {
			if tr.From == state {
				inputs[tr.Input] = true
			}
		}

		if len(inputs) != 256 {
			t.Errorf("state %d does not read every byte (got %d)", state, len(inputs))
		}
	}
}

func TestNoTransitionLeadsToAStateWithoutTransitions(t *testing.T) {
	dfa := DFA()
	fromStates := make(map[beeper.StateId]bool)
	for _, tr := range dfa.IterTransitions() {
		fromStates[tr.From] = true
	}

	for _, tr := range dfa.IterTransitions() {
		to := tr.To
		if to != SDead && to != SName && !fromStates[to] {
			t.Errorf("state %d leads nowhere", to)
		}
	}
}

func TestEveryRepresentationTransitionCarriesAnActionOfItsOwn(t *testing.T) {
	dfa := DFA()
	states := make(map[beeper.StateId]bool)
	for _, s := range representationStates() {
		states[s] = true
	}

	for _, tr := range dfa.IterTransitions() {
		if !states[tr.From] {
			continue
		}

		if tr.Action == nil {
			t.Errorf("the transition 0x%02x out of state %d carries no action", tr.Input, tr.From)
		}
	}
}

func TestAPatternCapturesWhereItEnds(t *testing.T) {
	mid := beeper.MatchId(0)
	dfa := DFA()
	dfa.StartPattern(SName).
		PushBytes([]byte("beep")).
		With(ActionCapture(mid))

	var captures []beeper.StateId
	for _, tr := range dfa.IterTransitions() {
		if tr.Action != nil && tr.Action.Kind == KindCapture {
			captures = append(captures, tr.From)
		}
	}

	if len(captures) != 1 {
		t.Fatalf("the capture is not on the last transition alone: got %d captures", len(captures))
	}
}

func TestHuffmanEncodeDecodeRoundtrip(t *testing.T) {
	cases := []string{
		"www.example.com",
		":method",
		":path",
		"/index.html",
		"custom-key",
		"custom-value-12345",
		"gzip, deflate",
	}

	for _, str := range cases {
		var encoded []byte
		if err := HuffmanEncode([]byte(str), &encoded); err != nil {
			t.Fatalf("encode failed for %q: %v", str, err)
		}

		decoded, err := HuffmanDecode(encoded)
		if err != nil {
			t.Fatalf("decode failed for %q: %v", str, err)
		}

		if !bytes.Equal(decoded, []byte(str)) {
			t.Fatalf("roundtrip mismatch for %q: got %q", str, string(decoded))
		}
	}
}
