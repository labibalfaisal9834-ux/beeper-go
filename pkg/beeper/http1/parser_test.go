package http1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lerboe/beeper-go/pkg/beeper"
)

func hdr(i uint8) string {
	return fmt.Sprintf("x-%d", i)
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
	names := []string{
		hdr(0),
		beeper.PseudoHeaderMethod.AsStr(),
		beeper.PseudoHeaderPath.AsStr(),
		beeper.PseudoHeaderStatus.AsStr(),
	}

	for _, name := range names {
		p := New()
		first, err := p.CaptureHdr(name)
		if err != nil {
			t.Fatalf("first capture for %s failed: %v", name, err)
		}
		second, err := p.CaptureHdr(name)
		if err != nil {
			t.Fatalf("second capture for %s failed: %v", name, err)
		}

		if first != second {
			t.Fatalf("capturing %s twice handed out two ids for one range: %v vs %v", name, first, second)
		}
	}
}

func TestMatchHttp2PrefaceAndCompileTables(t *testing.T) {
	p := New()
	mid, err := p.MatchHttp2Preface()
	if err != nil {
		t.Fatalf("match HTTP2 preface failed: %v", err)
	}
	if mid.Value() != 0 {
		t.Fatalf("expected mid 0, got %d", mid.Value())
	}

	_, err = p.CaptureHdr("user-agent")
	if err != nil {
		t.Fatalf("capture header failed: %v", err)
	}

	p.DoneOnHdrEnd()

	s2ts, a2as, err := p.CompileTables()
	if err != nil {
		t.Fatalf("compile tables failed: %v", err)
	}

	// Verify that table has non-zero entries
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
		t.Fatalf("compiled transition table is completely empty")
	}

	// Action table has valid actions
	hasActions := false
	for i := 1; i < MaxActions; i++ {
		if a2as[i].Kind != 0 || a2as[i].Flags != 0 {
			hasActions = true
			break
		}
	}
	if !hasActions {
		t.Fatalf("compiled action table has no actions")
	}
}
