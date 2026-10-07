package http2

import (
	"github.com/lerboe/beeper-go/pkg/beeper"
)

// Reserved DFA state IDs for HTTP/2 HPACK parsing.
// Must stay in sync with S_* constants of http2/parser.bpf.c.
const (
	SDead           beeper.StateId = 2
	SField          beeper.StateId = 3
	SKeyLen         beeper.StateId = 4
	SValLen         beeper.StateId = 5
	SName           beeper.StateId = 6
	SIdx7Cont       beeper.StateId = 7
	SIdx6Cont       beeper.StateId = 8
	SIdx4Cont       beeper.StateId = 9
	SStgCont        beeper.StateId = 10
	SKeyLenCont     beeper.StateId = 11
	SKeyLenContHuff beeper.StateId = 12
	SValLenCont     beeper.StateId = 13
	SValLenContHuff beeper.StateId = 14
	SReserved       uint16         = 15
)

// Action flags.
const (
	FHuff  uint8 = 1 << 0
	FAddDt uint8 = 1 << 1
	FCont  uint8 = 1 << 2
)

// Kind represents the HTTP/2 DFA action kind.
type Kind uint8

const (
	KindNone Kind = iota
	KindIndexed
	KindIdxName
	KindLitName
	KindKeyLen
	KindValLen
	KindTableSize
	KindIntStart
	KindIntCont
	KindCapture
	KindErr
)

// Action represents a DFA action for HTTP/2.
type Action struct {
	Kind  Kind
	Val   uint16
	Flags uint8
}

// NewAction creates an Action with kind, val, and flags.
func NewAction(kind Kind, val uint16, flags uint8) Action {
	return Action{
		Kind:  kind,
		Val:   val,
		Flags: flags,
	}
}

// ActionCapture creates an action for capturing a match id.
func ActionCapture(mid beeper.MatchId) Action {
	return NewAction(KindCapture, uint16(mid.Value()), 0)
}

// RawAction is the eBPF C ABI layout for struct http2_action.
type RawAction struct {
	Val   uint16
	Kind  uint8
	Flags uint8
}

// ToRaw converts Action to RawAction matching eBPF struct layout.
func (a Action) ToRaw() RawAction {
	return RawAction{
		Val:   a.Val,
		Kind:  uint8(a.Kind),
		Flags: a.Flags,
	}
}
