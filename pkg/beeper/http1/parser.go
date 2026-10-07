package http1

import (
	"fmt"
	"strings"

	"github.com/lerboe/beeper-go/pkg/beeper"
)

const (
	cr = "\r"
	lf = "\n"

	// MaxMatches is the maximum number of capture ranges a parser can hold.
	MaxMatches uint8 = 32

	// MaxStates is the maximum number of DFA states for HTTP/1.1 in eBPF.
	MaxStates = 512

	// MaxActions is the maximum number of distinct actions in eBPF.
	MaxActions = 256

	// MaxEdges is the maximum number of edges per state (256 byte inputs + AnyInput).
	MaxEdges = 257
)

// Parser compiles HTTP/1.1 patterns into a DFA for kernel injection.
type Parser struct {
	dfa        *beeper.DFA[Action]
	numMatches uint8
	parseFns   map[beeper.MessageBuffer]string
	matchedFn  string
	extractFns map[beeper.MessageBuffer]string
	captures   map[string]beeper.MatchId
}

// New creates a new HTTP/1.1 parser.
func New() *Parser {
	return &Parser{
		dfa:        beeper.NewDFA[Action](),
		numMatches: 0,
		parseFns:   make(map[beeper.MessageBuffer]string),
		extractFns: make(map[beeper.MessageBuffer]string),
		captures:   make(map[string]beeper.MatchId),
	}
}

// DFA returns the underlying DFA.
func (p *Parser) DFA() *beeper.DFA[Action] {
	return p.dfa
}

// NumMatches returns the number of configured matches.
func (p *Parser) NumMatches() uint8 {
	return p.numMatches
}

// ParseFns returns the configured parse function names.
func (p *Parser) ParseFns() map[beeper.MessageBuffer]string {
	return p.parseFns
}

// MatchedFn returns the configured matched function name.
func (p *Parser) MatchedFn() string {
	return p.matchedFn
}

// ExtractFns returns the configured extract function names.
func (p *Parser) ExtractFns() map[beeper.MessageBuffer]string {
	return p.extractFns
}

// Captures returns the map of header name to MatchId.
func (p *Parser) Captures() map[string]beeper.MatchId {
	return p.captures
}

// ParseFn configures the stub function to replace for the given buffer type.
func (p *Parser) ParseFn(fn string, msgBuf beeper.MessageBuffer) *Parser {
	p.parseFns[msgBuf] = fn
	return p
}

// SetMatchedFn configures the stub function to replace for BEEPER_MATCHED.
func (p *Parser) SetMatchedFn(fn string) *Parser {
	p.matchedFn = fn
	return p
}

// ExtractFn configures the stub function to replace for BEEPER_EXTRACT_MATCH_*.
func (p *Parser) ExtractFn(fn string, msgBuf beeper.MessageBuffer) *Parser {
	p.extractFns[msgBuf] = fn
	return p
}

func (p *Parser) newMatch() (beeper.MatchId, error) {
	if p.numMatches >= MaxMatches {
		return 0, &beeper.ErrMatchLimitExceeded{Limit: int(MaxMatches)}
	}
	id := beeper.MatchId(p.numMatches)
	p.numMatches++
	return id, nil
}

// CaptureHdr configures the parser to capture the value of a header field.
func (p *Parser) CaptureHdr(name string) (beeper.MatchId, error) {
	nameLower := strings.ToLower(name)
	if mid, ok := p.captures[nameLower]; ok {
		return mid, nil
	}

	mid, err := p.captureNewHdr(nameLower)
	if err != nil {
		return 0, err
	}
	p.captures[nameLower] = mid
	return mid, nil
}

func (p *Parser) captureNewHdr(name string) (beeper.MatchId, error) {
	if name == beeper.PseudoHeaderMethod.AsStr() || name == beeper.PseudoHeaderPath.AsStr() {
		return p.captureStatusLine(name)
	} else if name == beeper.PseudoHeaderStatus.AsStr() {
		return p.captureStatusCode()
	}

	mid, err := p.newMatch()
	if err != nil {
		return 0, err
	}

	pattern := p.dfa.StartPattern(beeper.AnyState)
	pattern.
		Push(lf).
		PushCI(name).
		PushOptional("\t", true).
		PushOptional(" ", true).
		PushCI(":").
		PushOptional("\t", true).
		PushOptional(" ", true).
		With(ActionStartCapture(mid))

	value := pattern.State()
	pattern.
		PushAny(1, -1).
		With(ActionEndCapture(mid)).
		PushOptional(cr, false).
		RestartWith(lf)

	p.dfa.StartPattern(value).
		PushOptional(cr, false).
		RestartWith(lf)

	return mid, nil
}

// MatchHttp2Preface configures the parser to match the HTTP/2 connection preface.
func (p *Parser) MatchHttp2Preface() (beeper.MatchId, error) {
	mid, err := p.newMatch()
	if err != nil {
		return 0, err
	}

	prefaceStr := fmt.Sprintf("PRI * HTTP/2.0%s%s%s%sSM%s%s%s%s", cr, lf, cr, lf, cr, lf, cr, lf)
	p.dfa.StartPattern(beeper.InitState).
		With(ActionStartCapture(mid)).
		Push(prefaceStr).
		With(ActionEndCaptureAndDone(mid))

	return mid, nil
}

func (p *Parser) captureStatusLine(name string) (beeper.MatchId, error) {
	methods := []string{
		"POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
	}

	mid, err := p.newMatch()
	if err != nil {
		return 0, err
	}

	if name == beeper.PseudoHeaderMethod.AsStr() {
		p.dfa.StartPattern(beeper.InitState).
			With(ActionStartCapture(mid)).
			PushOptionsCI(methods).
			With(ActionEndCapture(mid)).
			Push(" ").
			PushAny(1, -1).
			PushCI(" HTTP/1.1").
			PushOptional(cr, false).
			RestartWith(lf)
	} else if name == beeper.PseudoHeaderPath.AsStr() {
		p.dfa.StartPattern(beeper.InitState).
			PushOptionsCI(methods).
			Push(" ").
			With(ActionStartCapture(mid)).
			PushAny(1, -1).
			With(ActionEndCapture(mid)).
			PushCI(" HTTP/1.1").
			PushOptional(cr, false).
			RestartWith(lf)
	} else {
		panic(fmt.Sprintf("captureStatusLine called with unsupported header name: %s", name))
	}

	return mid, nil
}

func (p *Parser) captureStatusCode() (beeper.MatchId, error) {
	mid, err := p.newMatch()
	if err != nil {
		return 0, err
	}

	p.dfa.StartPattern(beeper.InitState).
		PushCI("HTTP/1.1 ").
		With(ActionStartCapture(mid)).
		PushAny(3, 3).
		With(ActionEndCapture(mid)).
		PushAny(1, -1).
		PushOptional(cr, false).
		RestartWith(lf)

	return mid, nil
}

// DoneOnHdrEnd configures the parser to terminate parsing on the empty line ending the header block.
func (p *Parser) DoneOnHdrEnd() *Parser {
	p.dfa.StartPattern(beeper.AnyState).
		PushOptional(cr, false).
		Push(lf).
		PushOptional(cr, false).
		Push(lf).
		With(ActionDone())

	return p
}

// CompileTables compiles the DFA into eBPF-compatible transition and action tables.
func (p *Parser) CompileTables() ([MaxStates][MaxEdges]Trans, [MaxActions]RawAction, error) {
	var s2ts [MaxStates][MaxEdges]Trans
	var a2as [MaxActions]RawAction

	numStates := int(p.dfa.NumStates())
	if numStates > MaxStates {
		return s2ts, a2as, beeper.ErrParserExceedsStateLimit
	}

	actionIdx := make(map[Action]uint16)
	// action index 0 is reserved for noop
	var nextActionIdx uint16 = 1

	for _, t := range p.dfa.IterTransitions() {
		var actionID uint16 = 0
		if t.Action != nil {
			act := *t.Action
			if idx, ok := actionIdx[act]; ok {
				actionID = idx
			} else {
				if int(nextActionIdx) >= MaxActions {
					return s2ts, a2as, beeper.ErrParserExceedsStateLimit
				}
				actionID = nextActionIdx
				actionIdx[act] = actionID
				a2as[actionID] = act.ToRaw()
				nextActionIdx++
			}
		}

		if int(t.From) >= MaxStates || int(t.Input) >= MaxEdges {
			return s2ts, a2as, beeper.ErrParserExceedsStateLimit
		}

		s2ts[t.From][t.Input] = Trans{
			State:  uint16(t.To),
			Action: actionID,
		}
	}

	return s2ts, a2as, nil
}
