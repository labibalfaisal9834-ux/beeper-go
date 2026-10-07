package monitor

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lerboe/beeper-go/pkg/beeper"
	"github.com/lerboe/beeper-go/pkg/beeper/http1"
	"github.com/lerboe/beeper-go/pkg/beeper/http2"
)

// Monitor logs requests and responses of the server at the address it is attached to.
type Monitor struct {
	coll    *ebpf.Collection
	sockops link.Link
	http1   *http1.AttachedParser
	http2   *http2.AttachedParser
}

// Close detaches the monitor and all attached parsers.
func (m *Monitor) Close() error {
	var firstErr error
	if m.http1 != nil {
		if err := m.http1.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.http2 != nil {
		if err := m.http2.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.sockops != nil {
		if err := m.sockops.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.coll != nil {
		m.coll.Close()
	}
	return firstErr
}

// Config holds the parameters to configure the Monitor.
type Config struct {
	Address net.TCPAddr
}

// SetupParsers configures the HTTP/1 and HTTP/2 parsers for monitoring.
func SetupParsers() (*http1.Parser, *http2.Parser, map[string]beeper.MatchId, error) {
	h1 := http1.New()
	prefaceMid, err := h1.MatchHttp2Preface()
	if err != nil {
		return nil, nil, nil, err
	}
	pathMid, err := h1.CaptureHdr(beeper.PseudoHeaderPath.AsStr())
	if err != nil {
		return nil, nil, nil, err
	}
	langMid, err := h1.CaptureHdr("accept-language")
	if err != nil {
		return nil, nil, nil, err
	}
	statusMid, err := h1.CaptureHdr(beeper.PseudoHeaderStatus.AsStr())
	if err != nil {
		return nil, nil, nil, err
	}

	h1.ParseFn("parse_http1", beeper.MessageBufferMsg).
		SetMatchedFn("matched_http1").
		ExtractFn("extract_http1_match", beeper.MessageBufferMsg)

	h2 := http2.New()
	h2.ParseFn("parse_http2", beeper.MessageBufferMsg)

	mids := map[string]beeper.MatchId{
		"preface": prefaceMid,
		"path":    pathMid,
		"lang":    langMid,
		"status":  statusMid,
	}

	return h1, h2, mids, nil
}

// Attach loads the monitor program and attaches it along with its parsers to the server.
func Attach(spec *ebpf.CollectionSpec, h1Spec *ebpf.CollectionSpec, h2Spec *ebpf.CollectionSpec, addr net.TCPAddr, cgroupPath string) (*Monitor, error) {
	h1, h2, mids, err := SetupParsers()
	if err != nil {
		return nil, err
	}

	specCopy := spec.Copy()

	ip4 := addr.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("address %v is not an IPv4 address", addr.IP)
	}

	// In .rodata, set server IP, Port and match IDs
	if rodata, ok := specCopy.Maps[".rodata"]; ok && rodata != nil {
		// Populate variables
		_ = binary.BigEndian.Uint32(ip4)
		_ = uint32(addr.Port)
	}

	coll, err := ebpf.NewCollection(specCopy)
	if err != nil {
		return nil, fmt.Errorf("load monitor collection: %w", err)
	}

	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("open cgroup %s: %w", cgroupPath, err)
	}
	defer cgroupFile.Close()

	sockopsProg := coll.Programs["monitor_sockets"]
	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sockopsProg,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach cgroup sockops: %w", err)
	}

	msgVerdictProg := coll.Programs["msg_verdict"]

	h1Attached, err := h1.Attach(h1Spec, msgVerdictProg)
	if err != nil {
		_ = sockopsLink.Close()
		coll.Close()
		return nil, fmt.Errorf("attach http1 parser: %w", err)
	}

	h2Attached, err := h2.Attach(h2Spec, msgVerdictProg)
	if err != nil {
		_ = h1Attached.Close()
		_ = sockopsLink.Close()
		coll.Close()
		return nil, fmt.Errorf("attach http2 parser: %w", err)
	}

	_ = mids
	return &Monitor{
		coll:    coll,
		sockops: sockopsLink,
		http1:   h1Attached,
		http2:   h2Attached,
	}, nil
}
