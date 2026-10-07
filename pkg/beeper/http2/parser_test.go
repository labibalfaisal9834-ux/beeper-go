package http2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lerboe/beeper-go/pkg/beeper"
)

func hdr(i uint8) []byte {
	return []byte(fmt.Sprintf("x-%d", i))
}

func TestAParserCapturesAtMostMaxMatchesRanges(t *testing.T) {
	p := New()
	for i := uint8(0); i < MaxMatches; i++ {
		mid, err := p.CaptureHdr(hdr(i))
		if err != nil {
			t.Fatalf("capture header %d failed: %v", i, err)
		}
		if mid.Value() != i {
			t.Fatalf("expected mid %d, got %d", i, mid.Value())
		}
	}

	_, err := p.CaptureHdr(hdr(MaxMatches))
	if err == nil {
		t.Fatalf("expected error on exceeding MaxMatches")
	}

	var matchErr *beeper.ErrMatchLimitExceeded
	if !errors.As(err, &matchErr) || matchErr.Limit != int(MaxMatches) {
		t.Fatalf("expected ErrMatchLimitExceeded with limit %d, got %v", MaxMatches, err)
	}
}

func TestTheSameHeaderIsCapturedUnderOneMatchID(t *testing.T) {
	names := [][]byte{
		hdr(0),
		[]byte(beeper.PseudoHeaderMethod.AsStr()),
		[]byte(beeper.PseudoHeaderPath.AsStr()),
		[]byte(beeper.PseudoHeaderStatus.AsStr()),
	}

	for _, name := range names {
		p := New()
		first, err := p.CaptureHdr(name)
		if err != nil {
			t.Fatalf("first capture for %s failed: %v", string(name), err)
		}
		second, err := p.CaptureHdr(name)
		if err != nil {
			t.Fatalf("second capture for %s failed: %v", string(name), err)
		}

		if first != second {
			t.Fatalf("capturing %s twice handed out two ids for one range: %v vs %v", string(name), first, second)
		}
	}
}

func TestBuildStaticTableEntries(t *testing.T) {
	p := New()
	entries, err := p.BuildStaticTableEntries()
	if err != nil {
		t.Fatalf("BuildStaticTableEntries failed: %v", err)
	}

	if len(entries) != 61 {
		t.Fatalf("expected 61 static table entries, got %d", len(entries))
	}

	// Index 2 is :method GET
	entry2, ok := entries[2]
	if !ok {
		t.Fatalf("entry 2 not found")
	}
	if entry2.KeyLen == 0 || entry2.ValLen == 0 {
		t.Fatalf("entry 2 has zero key/val len")
	}

	keyDecoded, err := HuffmanDecode(entry2.Key[:entry2.KeyLen])
	if err != nil || string(keyDecoded) != ":method" {
		t.Fatalf("entry 2 key decode failed: got %q, err: %v", string(keyDecoded), err)
	}

	valDecoded, err := HuffmanDecode(entry2.Val[:entry2.ValLen])
	if err != nil || string(valDecoded) != "GET" {
		t.Fatalf("entry 2 val decode failed: got %q, err: %v", string(valDecoded), err)
	}
}

func TestCompileTables(t *testing.T) {
	p := New()
	_, err := p.CaptureHdr([]byte(":path"))
	if err != nil {
		t.Fatalf("capture :path failed: %v", err)
	}
	_, err = p.CaptureHdr([]byte("content-length"))
	if err != nil {
		t.Fatalf("capture content-length failed: %v", err)
	}

	s2ts, a2as, err := p.CompileTables()
	if err != nil {
		t.Fatalf("CompileTables failed: %v", err)
	}

	// Verify transitions exist
	hasTransitions := false
	for s := 0; s < MaxStates; s++ {
		for inp := 0; inp < MaxEdges; inp++ {
			if s2ts[s][inp].State != 0 || s2ts[s][inp].Action != 0 {
				hasTransitions = true
				break
			}
		}
	}
	if !hasTransitions {
		t.Fatalf("compiled transition table is empty")
	}

	// Verify actions exist
	hasActions := false
	for i := 1; i < MaxActions; i++ {
		if a2as[i].Kind != 0 {
			hasActions = true
			break
		}
	}
	if !hasActions {
		t.Fatalf("compiled action table is empty")
	}
}
