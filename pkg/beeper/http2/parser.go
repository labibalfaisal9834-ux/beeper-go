package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/lerboe/beeper-go/pkg/beeper"
)

const (
	// MaxMatches is the maximum number of capture ranges (32).
	MaxMatches uint8 = 32

	// DynamicTableBase is the index where the dynamic table begins (62).
	DynamicTableBase uint32 = 62

	// HeaderFieldMaxLen is the maximum bytes stored for key/val in a table entry (128).
	HeaderFieldMaxLen = 128

	// MaxStates is the maximum number of DFA states for HTTP/2 in eBPF.
	MaxStates = 1024

	// MaxActions is the maximum number of actions in eBPF.
	MaxActions = 1024

	// MaxEdges is the maximum number of byte inputs (256).
	MaxEdges = 256
)

// IP4Addr represents an IPv4 endpoint in eBPF.
// IP4 is stored in network byte order (be), Port in host byte order.
type IP4Addr struct {
	IP4  uint32
	Port uint32
}

// IP4Conn represents a pair of IPv4 endpoints identifying a connection.
type IP4Conn struct {
	Local  IP4Addr
	Remote IP4Addr
}

// Http2HdrField represents struct http2_hdr_field in eBPF.
type Http2HdrField struct {
	Key     [HeaderFieldMaxLen]byte
	KeyLen  uint8
	Val     [HeaderFieldMaxLen]byte
	ValLen  uint8
	KeyHuff uint8
	ValHuff uint8
}

// DynamicTableKey represents struct dynamic_table_key in eBPF.
type DynamicTableKey struct {
	Conn IP4Conn
	Idx  uint32
}

// DynamicTableInfo represents the connection's dynamic table metadata (struct dynamic_table_info in eBPF).
type DynamicTableInfo struct {
	Count   uint32
	Size    uint32
	MaxSize uint32
	Deleted uint32
	Dirty   uint32
}

// Trans represents struct trans in eBPF.
type Trans struct {
	State  uint16
	Action uint16
}

// Parser for HTTP/2 messages.
type Parser struct {
	dfa                    *beeper.DFA[Action]
	numMatches             uint8
	parseFns               map[beeper.MessageBuffer]string
	matchedFn              string
	extractFns             map[beeper.MessageBuffer]string
	getDynamicTableEntryFn string
	captures               map[string]beeper.MatchId
}

// New creates a new HTTP/2 parser initialized with the HPACK DFA.
func New() *Parser {
	return &Parser{
		dfa:        DFA(),
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

// NumMatches returns the count of captures.
func (p *Parser) NumMatches() uint8 {
	return p.numMatches
}

// Captures returns the map of header wire names to MatchId.
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

// GetDynamicTableEntry configures the stub function to replace for BEEPER_HTTP2_GET_DT_ENTRY.
func (p *Parser) GetDynamicTableEntry(fn string) *Parser {
	p.getDynamicTableEntryFn = fn
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

// CaptureHdr configures the parser to capture the value of a header field (bytes).
func (p *Parser) CaptureHdr(name []byte) (beeper.MatchId, error) {
	nameKey := string(name)
	if mid, ok := p.captures[nameKey]; ok {
		return mid, nil
	}

	var nameEncoded []byte
	if err := HuffmanEncode(name, &nameEncoded); err != nil {
		return 0, &beeper.ErrInvalidEncoding{Err: err}
	}

	mid, err := p.newMatch()
	if err != nil {
		return 0, err
	}

	p.dfa.StartPattern(SName).
		PushBytes(nameEncoded).
		With(ActionCapture(mid))

	p.captures[nameKey] = mid
	return mid, nil
}

// CaptureHdrString configures the parser to capture the value of a header field (string).
func (p *Parser) CaptureHdrString(name string) (beeper.MatchId, error) {
	return p.CaptureHdr([]byte(name))
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

// BuildStaticTableEntries constructs the 61 HPACK static table entries in Huffman-coded format.
func (p *Parser) BuildStaticTableEntries() (map[uint32]Http2HdrField, error) {
	stKeys, stHfs := CreateHeaderMaps()
	entries := make(map[uint32]Http2HdrField)

	insert := func(idx uint32, key string, val *string) error {
		var hfKey []byte
		if err := HuffmanEncode([]byte(key), &hfKey); err != nil {
			return err
		}

		var hfVal []byte
		if val != nil {
			if err := HuffmanEncode([]byte(*val), &hfVal); err != nil {
				return err
			}
		}

		var hf Http2HdrField
		copy(hf.Key[:], hfKey)
		hf.KeyLen = uint8(len(hfKey))
		copy(hf.Val[:], hfVal)
		hf.ValLen = uint8(len(hfVal))
		hf.KeyHuff = 1
		hf.ValHuff = 1

		entries[idx] = hf
		return nil
	}

	for key, vals := range stHfs {
		for val, idx := range vals {
			v := val
			if err := insert(uint32(idx), key, &v); err != nil {
				return nil, err
			}
		}
	}

	for key, idx := range stKeys {
		if err := insert(uint32(idx), key, nil); err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// IP4AddrFromNetIP converts a net.IP and port into IP4Addr.
func IP4AddrFromNetIP(ip net.IP, port int) (IP4Addr, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return IP4Addr{}, errors.New("not an IPv4 address")
	}
	return IP4Addr{
		IP4:  binary.BigEndian.Uint32(ip4),
		Port: uint32(port),
	}, nil
}

// IP4AddrFromAddrPort converts a netip.AddrPort into IP4Addr.
func IP4AddrFromAddrPort(ap netip.AddrPort) (IP4Addr, error) {
	if !ap.Addr().Is4() {
		return IP4Addr{}, errors.New("not an IPv4 address")
	}
	b := ap.Addr().As4()
	return IP4Addr{
		IP4:  binary.BigEndian.Uint32(b[:]),
		Port: uint32(ap.Port()),
	}, nil
}

// DecodeDynamicTableInfo decodes binary map values into DynamicTableInfo.
func DecodeDynamicTableInfo(data []byte) (DynamicTableInfo, error) {
	if len(data) < 20 {
		return DynamicTableInfo{}, errors.New("dynamic_table_info buffer too short")
	}
	var info DynamicTableInfo
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.NativeEndian, &info); err != nil {
		return DynamicTableInfo{}, err
	}
	return info, nil
}
