package http1

import (
	"github.com/lerboe/beeper-go/pkg/beeper"
)

// The kinds and flags below stay in sync with the HTTP1A_* and HTTP1F_*
// constants of http1/parser.bpf.c.

const (
	// HTTP1ANone is a no-op action (default).
	HTTP1ANone uint8 = 0

	// HTTP1AStartCapture starts capturing with the next byte.
	HTTP1AStartCapture uint8 = 1

	// HTTP1AEndCapture ends capturing with the next byte.
	HTTP1AEndCapture uint8 = 2

	// HTTP1FDone terminates parsing and skips the remainder of the message.
	HTTP1FDone uint8 = 1 << 0
)

// ActionKind represents the high-level DFA action for HTTP/1.1.
type ActionKind uint8

const (
	// ActionKindDone terminates parsing.
	ActionKindDone ActionKind = iota
	// ActionKindStartCapture begins a match capture range.
	ActionKindStartCapture
	// ActionKindEndCapture ends a match capture range.
	ActionKindEndCapture
	// ActionKindEndCaptureAndDone ends capture and completes parsing.
	ActionKindEndCaptureAndDone
)

// Action represents an action attached to a DFA transition.
type Action struct {
	Kind ActionKind
	Mid  beeper.MatchId
}

// ActionDone creates a Done action.
func ActionDone() Action {
	return Action{Kind: ActionKindDone}
}

// ActionStartCapture creates a StartCapture action with mid.
func ActionStartCapture(mid beeper.MatchId) Action {
	return Action{Kind: ActionKindStartCapture, Mid: mid}
}

// ActionEndCapture creates an EndCapture action with mid.
func ActionEndCapture(mid beeper.MatchId) Action {
	return Action{Kind: ActionKindEndCapture, Mid: mid}
}

// ActionEndCaptureAndDone creates an EndCaptureAndDone action with mid.
func ActionEndCaptureAndDone(mid beeper.MatchId) Action {
	return Action{Kind: ActionKindEndCaptureAndDone, Mid: mid}
}

// RawAction is the eBPF C ABI layout for struct http1_action.
type RawAction struct {
	Kind  uint8
	Flags uint8
	Mid   uint8
}

// ToRaw converts the high-level Action to the eBPF RawAction.
func (a Action) ToRaw() RawAction {
	switch a.Kind {
	case ActionKindDone:
		return RawAction{Kind: HTTP1ANone, Flags: HTTP1FDone, Mid: 0}
	case ActionKindStartCapture:
		return RawAction{Kind: HTTP1AStartCapture, Flags: 0, Mid: a.Mid.Value()}
	case ActionKindEndCapture:
		return RawAction{Kind: HTTP1AEndCapture, Flags: 0, Mid: a.Mid.Value()}
	case ActionKindEndCaptureAndDone:
		return RawAction{Kind: HTTP1AEndCapture, Flags: HTTP1FDone, Mid: a.Mid.Value()}
	default:
		return RawAction{}
	}
}

// Trans represents a transition entry (struct trans) in eBPF.
type Trans struct {
	State  uint16
	Action uint16
}
