package beeper

import (
	"fmt"
	"strconv"
)

// InitState is the state a message is parsed from.
const InitState StateId = 0

// AnyState is the fallback state, to which all edges lead if no input matched.
const AnyState StateId = 1

// Input is what a transition is matched on: a byte of the message (0..255), or AnyInput.
type Input uint16

// AnyInput is the input a state matches any byte with.
const AnyInput Input = 0x100

// Edge represents a single transition of a DFA.
type Edge[A comparable] struct {
	To     StateId
	Action *A
}

// OptionalPrefix is an input sequence of a pattern that may be skipped.
type OptionalPrefix struct {
	Inputs        []Input
	CaseSensitive bool
	Repeat        bool
}

type lastEdge struct {
	From          StateId
	Input         Input
	CaseSensitive bool
}

// DFABuilder builds a single pattern into a DFA.
type DFABuilder[A comparable] struct {
	dfa              *DFA[A]
	state            StateId
	optionalPrefixes []OptionalPrefix
	optionalStates   []StateId
	lastEdges        []lastEdge
}

func newDFABuilder[A comparable](dfa *DFA[A], state StateId) *DFABuilder[A] {
	return &DFABuilder[A]{
		dfa:   dfa,
		state: state,
	}
}

// State returns the state the pattern has been built up to.
func (b *DFABuilder[A]) State() StateId {
	return b.state
}

// With attaches action to every transition that leads into the current state.
func (b *DFABuilder[A]) With(action A) *DFABuilder[A] {
	b.pushOptionalPrefixes()

	for _, edge := range b.lastEdges {
		b.dfa.AddAction(edge.From, edge.Input, action)

		if !edge.CaseSensitive {
			if other, ok := otherCase(edge.Input); ok {
				b.dfa.AddAction(edge.From, other, action)
			}
		}
	}

	return b
}

func (b *DFABuilder[A]) pushOptionalPrefixes() {
	prefixes := b.optionalPrefixes
	b.optionalPrefixes = nil

	for _, prefix := range prefixes {
		sources := []StateId{b.state}
		sources = append(sources, b.optionalStates...)

		for _, source := range sources {
			from := source
			for i, input := range prefix.Inputs {
				var to *StateId
				if i == len(prefix.Inputs)-1 {
					b.lastEdges = append(b.lastEdges, lastEdge{
						From:          from,
						Input:         input,
						CaseSensitive: prefix.CaseSensitive,
					})
					if prefix.Repeat {
						s := source
						to = &s
					}
				}

				from = b.pushEdgeFrom(from, input, to, prefix.CaseSensitive)
			}

			if !prefix.Repeat && from != b.state && !containsState(b.optionalStates, from) {
				b.optionalStates = append(b.optionalStates, from)
			}
		}
	}
}

func (b *DFABuilder[A]) pushEdge(input Input, to *StateId, caseSensitive bool) {
	b.pushOptionalPrefixes()

	start := b.state
	toState := b.pushEdgeFrom(start, input, to, caseSensitive)
	b.lastEdges = []lastEdge{{From: start, Input: input, CaseSensitive: caseSensitive}}

	for _, from := range b.optionalStates {
		b.pushEdgeFrom(from, input, &toState, caseSensitive)
		b.lastEdges = append(b.lastEdges, lastEdge{From: from, Input: input, CaseSensitive: caseSensitive})
	}
	b.optionalStates = nil

	b.state = toState
}

func (b *DFABuilder[A]) pushEdgeFrom(from StateId, input Input, to *StateId, caseSensitive bool) StateId {
	var toState StateId
	if to != nil {
		toState = *to
	} else {
		toState = b.dfa.NextState(from, input)
	}

	b.dfa.InsertEdge(from, input, toState, nil)
	if !caseSensitive {
		if other, ok := otherCase(input); ok {
			b.dfa.InsertEdge(from, other, toState, nil)
		}
	}

	return toState
}

// Push appends input to the pattern case-sensitively.
func (b *DFABuilder[A]) Push(input string) *DFABuilder[A] {
	return b.pushInner([]byte(input), true)
}

// PushBytes appends raw bytes to the pattern case-sensitively.
func (b *DFABuilder[A]) PushBytes(input []byte) *DFABuilder[A] {
	return b.pushInner(input, true)
}

// PushCI appends input to the pattern case-insensitively.
func (b *DFABuilder[A]) PushCI(input string) *DFABuilder[A] {
	return b.pushInner([]byte(input), false)
}

func (b *DFABuilder[A]) pushInner(input []byte, caseSensitive bool) *DFABuilder[A] {
	for _, byteVal := range input {
		b.pushEdge(Input(byteVal), nil, caseSensitive)
	}
	return b
}

// PushAny pushes transitions matching any byte.
// If maxLen is omitted or negative, it represents an unbounded range [minLen..).
// If maxLen is specified and non-negative, it represents a bounded range [minLen..maxLen].
func (b *DFABuilder[A]) PushAny(minLen int, maxLen ...int) *DFABuilder[A] {
	if len(maxLen) == 0 || maxLen[0] < 0 {
		for i := 0; i < minLen; i++ {
			b.pushEdge(AnyInput, nil, true)
		}
		b.pushEdgeFrom(b.state, AnyInput, &b.state, true)
		b.lastEdges = append(b.lastEdges, lastEdge{From: b.state, Input: AnyInput, CaseSensitive: true})
		return b
	}

	max := maxLen[0]
	if minLen > max {
		panic("Cannot push an empty range")
	}

	for i := 0; i < minLen; i++ {
		b.pushEdge(AnyInput, nil, true)
	}

	for i := 0; i < max-minLen; i++ {
		b.optionalPrefixes = append(b.optionalPrefixes, OptionalPrefix{
			Inputs:        []Input{AnyInput},
			CaseSensitive: true,
			Repeat:        false,
		})
	}

	return b
}

// PushOptionsCI adds a set of case-insensitive alternative patterns.
func (b *DFABuilder[A]) PushOptionsCI(inputs []string) *DFABuilder[A] {
	return b.pushOptionsInner(inputs, false)
}

func (b *DFABuilder[A]) pushOptionsInner(inputs []string, caseSensitive bool) *DFABuilder[A] {
	if len(inputs) == 0 {
		return b
	}

	longest := inputs[0]
	for _, s := range inputs[1:] {
		if len(s) > len(longest) {
			longest = s
		}
	}

	start := b.state
	b.pushInner([]byte(longest), caseSensitive)
	finalState := b.state

	lastEdges := b.lastEdges
	b.lastEdges = nil

	for _, input := range inputs {
		if input == longest {
			continue
		}
		if len(input) == 0 {
			panic("Cannot push an empty option")
		}

		b.state = start
		for i := 0; i < len(input); i++ {
			var to *StateId
			if i == len(input)-1 {
				to = &finalState
			}
			b.pushEdge(Input(input[i]), to, caseSensitive)
		}

		lastEdges = append(lastEdges, b.lastEdges...)
	}

	b.lastEdges = lastEdges
	return b
}

// PushOptional appends an input that may be skipped.
func (b *DFABuilder[A]) PushOptional(input string, repeat bool) *DFABuilder[A] {
	inputs := make([]Input, len(input))
	for i := 0; i < len(input); i++ {
		inputs[i] = Input(input[i])
	}
	b.optionalPrefixes = append(b.optionalPrefixes, OptionalPrefix{
		Inputs:        inputs,
		CaseSensitive: true,
		Repeat:        repeat,
	})
	return b
}

// RestartWith matches input and transitions to the state the DFA would be in starting from AnyState.
func (b *DFABuilder[A]) RestartWith(input string) {
	state := AnyState
	for i := 0; i < len(input); i++ {
		c := Input(input[i])
		next := b.dfa.NextState(state, c)
		b.pushEdgeFrom(state, c, &next, false)
		state = next
	}
	finalState := state

	for i := 0; i < len(input); i++ {
		var to *StateId
		if i == len(input)-1 {
			to = &finalState
		}
		b.pushEdge(Input(input[i]), to, false)
	}
}

func otherCase(input Input) (Input, bool) {
	if input > 0xFF {
		return 0, false
	}
	b := byte(input)
	if b >= 'a' && b <= 'z' {
		return Input(b - 'a' + 'A'), true
	}
	if b >= 'A' && b <= 'Z' {
		return Input(b - 'A' + 'a'), true
	}
	return 0, false
}

func containsState(slice []StateId, target StateId) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// FmtInput renders input for diagnostics.
func FmtInput(input Input) string {
	if input <= 0xFF {
		return strconv.QuoteRune(rune(input))
	}
	return "<any>"
}

// Transition holds a single edge from the DFA.
type Transition[A comparable] struct {
	From   StateId
	Input  Input
	To     StateId
	Action *A
}

// DFA represents a Deterministic Finite Automaton with typed edge actions.
type DFA[A comparable] struct {
	numStates uint16
	edges     map[StateId]map[Input]Edge[A]
}

// NewDFA creates a DFA with InitState (0) and AnyState (1).
func NewDFA[A comparable]() *DFA[A] {
	return NewDFAWithReservedStates[A](2)
}

// NewDFAWithReservedStates creates a DFA reserving the first reserved states.
func NewDFAWithReservedStates[A comparable](reserved uint16) *DFA[A] {
	if reserved < 2 {
		reserved = 2
	}
	return &DFA[A]{
		numStates: reserved,
		edges:     make(map[StateId]map[Input]Edge[A]),
	}
}

// NumStates returns the total number of states in the DFA.
func (d *DFA[A]) NumStates() uint16 {
	return d.numStates
}

// StartPattern starts building a new pattern anchored at state.
func (d *DFA[A]) StartPattern(state StateId) *DFABuilder[A] {
	return newDFABuilder(d, state)
}

// NewState allocates and returns a new state ID.
func (d *DFA[A]) NewState() StateId {
	id := StateId(d.numStates)
	d.numStates++
	return id
}

// NextState returns the next state for (from, input), allocating one if none exists.
func (d *DFA[A]) NextState(from StateId, input Input) StateId {
	if edges, ok := d.edges[from]; ok {
		if edge, ok := edges[input]; ok {
			return edge.To
		}
	}
	return d.NewState()
}

// InsertEdge inserts a transition from `from` to `to` matching `input`.
func (d *DFA[A]) InsertEdge(from StateId, input Input, to StateId, action *A) {
	edges, ok := d.edges[from]
	if !ok {
		edges = make(map[Input]Edge[A])
		d.edges[from] = edges
	}

	old, exists := edges[input]
	if !exists {
		edges[input] = Edge[A]{To: to, Action: action}
		return
	}

	if old.To != to {
		panic(fmt.Sprintf("Cannot create a transition from %d to %d and %d", from, old.To, to))
	}

	switch {
	case action == nil:
		// keep existing action
	case old.Action == nil && action != nil:
		old.Action = action
		edges[input] = old
	case old.Action != nil && action != nil:
		if *old.Action != *action {
			panic(fmt.Sprintf("Cannot %v and %v on the same transition", *action, *old.Action))
		}
	}
}

// AddAction attaches an action to an existing transition.
func (d *DFA[A]) AddAction(from StateId, input Input, action A) {
	edges, ok := d.edges[from]
	if !ok {
		panic("State not found")
	}

	edge, ok := edges[input]
	if !ok {
		panic("Edge not found")
	}

	if edge.Action != nil && *edge.Action != action {
		panic(fmt.Sprintf("Cannot %v and %v on the same transition", action, *edge.Action))
	}

	edge.Action = &action
	edges[input] = edge
}

// IterTransitions returns all transitions currently in the DFA.
func (d *DFA[A]) IterTransitions() []Transition[A] {
	var res []Transition[A]
	for from, inputs := range d.edges {
		for input, edge := range inputs {
			res = append(res, Transition[A]{
				From:   from,
				Input:  input,
				To:     edge.To,
				Action: edge.Action,
			})
		}
	}
	return res
}

// GetEdge returns the edge for (from, input), if one exists.
func (d *DFA[A]) GetEdge(from StateId, input Input) (Edge[A], bool) {
	if edges, ok := d.edges[from]; ok {
		edge, exists := edges[input]
		return edge, exists
	}
	return Edge[A]{}, false
}
