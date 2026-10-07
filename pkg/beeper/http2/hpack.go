package http2

import (
	"github.com/lerboe/beeper-go/pkg/beeper"
)

// DFA builds the states and edges of every RFC 7541 HPACK field representation into a DFA.
func DFA() *beeper.DFA[Action] {
	dfa := beeper.NewDFAWithReservedStates[Action](SReserved)
	insertFieldRow(dfa)
	insertLengthRows(dfa)
	insertContinuationRows(dfa)
	return dfa
}

func insertFieldRow(dfa *beeper.DFA[Action]) {
	edge := func(input uint8, to beeper.StateId, action Action) {
		act := action
		dfa.InsertEdge(SField, beeper.Input(input), to, &act)
	}

	// Indexed field, 7-bit prefix. Index 0 is invalid/unused.
	edge(0x80, SDead, NewAction(KindErr, 0, 0))
	for idx := uint16(1); idx < 0x7F; idx++ {
		edge(0x80|uint8(idx), SField, NewAction(KindIndexed, idx, 0))
	}
	edge(0xFF, SIdx7Cont, NewAction(KindIntStart, 0x7F, 0))

	// Literal field added to dynamic table, 6-bit prefix.
	edge(0x40, SKeyLen, NewAction(KindLitName, 0, FAddDt))
	for idx := uint16(1); idx < 0x3F; idx++ {
		edge(0x40|uint8(idx), SValLen, NewAction(KindIdxName, idx, FAddDt))
	}
	edge(0x7F, SIdx6Cont, NewAction(KindIntStart, 0x3F, 0))

	// Dynamic table size update, 5-bit prefix.
	for size := uint16(0); size < 0x1F; size++ {
		edge(0x20|uint8(size), SField, NewAction(KindTableSize, size, 0))
	}
	edge(0x3F, SStgCont, NewAction(KindIntStart, 0x1F, 0))

	// Literal field not added to dynamic table, 4-bit prefix (0x00 and 0x10 bases).
	for _, base := range []uint8{0x00, 0x10} {
		edge(base, SKeyLen, NewAction(KindLitName, 0, 0))
		for idx := uint16(1); idx < 0x0F; idx++ {
			edge(base|uint8(idx), SValLen, NewAction(KindIdxName, idx, 0))
		}
		edge(base|0x0F, SIdx4Cont, NewAction(KindIntStart, 0x0F, 0))
	}
}

func insertLengthRows(dfa *beeper.DFA[Action]) {
	type lengthRow struct {
		from     beeper.StateId
		kind     Kind
		to       beeper.StateId
		cont     beeper.StateId
		contHuff beeper.StateId
	}

	rows := []lengthRow{
		{SKeyLen, KindKeyLen, SName, SKeyLenCont, SKeyLenContHuff},
		{SValLen, KindValLen, SField, SValLenCont, SValLenContHuff},
	}

	for _, row := range rows {
		type baseVariant struct {
			base  uint8
			flags uint8
			cont  beeper.StateId
		}

		variants := []baseVariant{
			{0x00, 0, row.cont},
			{0x80, FHuff, row.contHuff},
		}

		for _, v := range variants {
			for length := uint16(0); length < 0x7F; length++ {
				act := NewAction(row.kind, length, v.flags)
				dfa.InsertEdge(row.from, beeper.Input(v.base|uint8(length)), row.to, &act)
			}

			act := NewAction(KindIntStart, 0x7F, 0)
			dfa.InsertEdge(row.from, beeper.Input(v.base|0x7F), v.cont, &act)
		}
	}
}

func insertContinuationRows(dfa *beeper.DFA[Action]) {
	type contRow struct {
		from  beeper.StateId
		kind  Kind
		to    beeper.StateId
		flags uint8
	}

	rows := []contRow{
		{SIdx7Cont, KindIndexed, SField, 0},
		{SIdx6Cont, KindIdxName, SValLen, FAddDt},
		{SIdx4Cont, KindIdxName, SValLen, 0},
		{SStgCont, KindTableSize, SField, 0},
		{SKeyLenCont, KindKeyLen, SName, 0},
		{SKeyLenContHuff, KindKeyLen, SName, FHuff},
		{SValLenCont, KindValLen, SField, 0},
		{SValLenContHuff, KindValLen, SField, FHuff},
	}

	for _, row := range rows {
		for input := uint8(0); input < 0x80; input++ {
			act1 := NewAction(row.kind, 0, row.flags|FCont)
			dfa.InsertEdge(row.from, beeper.Input(input), row.to, &act1)

			act2 := NewAction(KindIntCont, 0, 0)
			dfa.InsertEdge(row.from, beeper.Input(0x80|input), row.from, &act2)
		}
	}
}

// CreateHeaderMaps returns the HPACK static table entries (RFC 7541 Appendix A).
func CreateHeaderMaps() (map[string]int, map[string]map[string]int) {
	headersWithoutValues := make(map[string]int)
	headersWithValues := make(map[string]map[string]int)

	headersWithoutValues[":authority"] = 1
	headersWithoutValues["accept-charset"] = 15
	headersWithoutValues["accept-language"] = 17
	headersWithoutValues["accept-ranges"] = 18
	headersWithoutValues["accept"] = 19
	headersWithoutValues["access-control-allow-origin"] = 20
	headersWithoutValues["age"] = 21
	headersWithoutValues["allow"] = 22
	headersWithoutValues["authorization"] = 23
	headersWithoutValues["cache-control"] = 24
	headersWithoutValues["content-disposition"] = 25
	headersWithoutValues["content-encoding"] = 26
	headersWithoutValues["content-language"] = 27
	headersWithoutValues["content-length"] = 28
	headersWithoutValues["content-location"] = 29
	headersWithoutValues["content-range"] = 30
	headersWithoutValues["content-type"] = 31
	headersWithoutValues["cookie"] = 32
	headersWithoutValues["date"] = 33
	headersWithoutValues["etag"] = 34
	headersWithoutValues["expect"] = 35
	headersWithoutValues["expires"] = 36
	headersWithoutValues["from"] = 37
	headersWithoutValues["host"] = 38
	headersWithoutValues["if-match"] = 39
	headersWithoutValues["if-modified-since"] = 40
	headersWithoutValues["if-none-match"] = 41
	headersWithoutValues["if-range"] = 42
	headersWithoutValues["if-unmodified-since"] = 43
	headersWithoutValues["last-modified"] = 44
	headersWithoutValues["link"] = 45
	headersWithoutValues["location"] = 46
	headersWithoutValues["max-forwards"] = 47
	headersWithoutValues["proxy-authenticate"] = 48
	headersWithoutValues["proxy-authorization"] = 49
	headersWithoutValues["range"] = 50
	headersWithoutValues["referer"] = 51
	headersWithoutValues["refresh"] = 52
	headersWithoutValues["retry-after"] = 53
	headersWithoutValues["server"] = 54
	headersWithoutValues["set-cookie"] = 55
	headersWithoutValues["strict-transport-security"] = 56
	headersWithoutValues["transfer-encoding"] = 57
	headersWithoutValues["user-agent"] = 58
	headersWithoutValues["vary"] = 59
	headersWithoutValues["via"] = 60
	headersWithoutValues["www-authenticate"] = 61

	// Headers with predefined values
	methodMap := make(map[string]int)
	methodMap["GET"] = 2
	methodMap["POST"] = 3
	headersWithValues[":method"] = methodMap

	pathMap := make(map[string]int)
	pathMap["/"] = 4
	pathMap["/index.html"] = 5
	headersWithValues[":path"] = pathMap

	schemeMap := make(map[string]int)
	schemeMap["http"] = 6
	schemeMap["https"] = 7
	headersWithValues[":scheme"] = schemeMap

	statusMap := make(map[string]int)
	statusMap["200"] = 8
	statusMap["204"] = 9
	statusMap["206"] = 10
	statusMap["304"] = 11
	statusMap["400"] = 12
	statusMap["404"] = 13
	statusMap["500"] = 14
	headersWithValues[":status"] = statusMap

	acceptEncodingMap := make(map[string]int)
	acceptEncodingMap["gzip, deflate"] = 16
	headersWithValues["accept-encoding"] = acceptEncodingMap

	return headersWithoutValues, headersWithValues
}
