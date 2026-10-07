package beeper

import (
	"errors"
	"fmt"
)

// MessageBuffer specifies the kernel buffer type the BPF parser runs on.
type MessageBuffer string

const (
	// MessageBufferSkb runs on sk_buff.
	MessageBufferSkb MessageBuffer = "skb"
	// MessageBufferMsg runs on sk_msg.
	MessageBufferMsg MessageBuffer = "msg"
)

// Common error values returned by parsers.
var (
	// ErrParserExceedsStateLimit is returned when patterns exceed the number of states or actions.
	ErrParserExceedsStateLimit = errors.New("the patterns do not fit into the parser program")
)

// ErrMatchLimitExceeded indicates that the parser has exceeded its maximum match capacity.
type ErrMatchLimitExceeded struct {
	Limit int
}

func (e *ErrMatchLimitExceeded) Error() string {
	return fmt.Sprintf("a parser captures at most %d ranges", e.Limit)
}

func (e *ErrMatchLimitExceeded) Is(target error) bool {
	t, ok := target.(*ErrMatchLimitExceeded)
	return ok && (t.Limit == 0 || t.Limit == e.Limit)
}

// ErrInvalidEncoding indicates a header name could not be Huffman encoded.
type ErrInvalidEncoding struct {
	Err error
}

func (e *ErrInvalidEncoding) Error() string {
	return fmt.Sprintf("the header name cannot be Huffman encoded: %v", e.Err)
}

func (e *ErrInvalidEncoding) Unwrap() error {
	return e.Err
}

// ErrBpf indicates the parser program could not be loaded into the kernel or attached.
type ErrBpf struct {
	Err error
}

func (e *ErrBpf) Error() string {
	return fmt.Sprintf("the parser program cannot be loaded: %v", e.Err)
}

func (e *ErrBpf) Unwrap() error {
	return e.Err
}

// ErrMalformedTableEntry indicates an entry read back from a map was malformed.
type ErrMalformedTableEntry struct {
	Err error
}

func (e *ErrMalformedTableEntry) Error() string {
	return fmt.Sprintf("the parser wrote a table entry back malformed: %v", e.Err)
}

func (e *ErrMalformedTableEntry) Unwrap() error {
	return e.Err
}

// PseudoHeaderName represents fields of a request or status line (e.g. :path, :method).
type PseudoHeaderName string

// AsStr returns the string representation.
func (p PseudoHeaderName) AsStr() string {
	return string(p)
}

func (p PseudoHeaderName) String() string {
	return string(p)
}

const (
	// PseudoHeaderMethod is the HTTP method (:method).
	PseudoHeaderMethod PseudoHeaderName = ":method"
	// PseudoHeaderPath is the request path (:path).
	PseudoHeaderPath PseudoHeaderName = ":path"
	// PseudoHeaderStatus is the response status code (:status).
	PseudoHeaderStatus PseudoHeaderName = ":status"
	// PseudoHeaderAuthority is the request authority (:authority).
	PseudoHeaderAuthority PseudoHeaderName = ":authority"
	// PseudoHeaderScheme is the request scheme (:scheme).
	PseudoHeaderScheme PseudoHeaderName = ":scheme"
)

// StateId identifies a state of the DFA.
// State 0 is the initial state, state 1 is the fallback state.
type StateId uint16

// MatchId identifies a captured range in the parse result (0..31).
type MatchId uint8

// Value returns the raw uint8 value of MatchId.
func (m MatchId) Value() uint8 {
	return uint8(m)
}
