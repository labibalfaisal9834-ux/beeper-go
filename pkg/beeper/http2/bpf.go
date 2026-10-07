package http2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lerboe/beeper-go/pkg/beeper"
)

// AttachedParser represents a loaded and attached HTTP/2 BPF parser.
type AttachedParser struct {
	dynamicTableInfo *ebpf.Map
	dynamicTable     *ebpf.Map
	continuedBlocks  *ebpf.Map
	links            []link.Link
	coll             *ebpf.Collection
}

// Close detaches the parser and closes all BPF resources.
func (ap *AttachedParser) Close() error {
	var firstErr error
	for _, l := range ap.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if ap.coll != nil {
		ap.coll.Close()
	}
	return firstErr
}

// DynamicTableInfo returns the state of the dynamic table for a connection.
func (ap *AttachedParser) DynamicTableInfo(local, remote netip.AddrPort) (DynamicTableInfo, error) {
	localAddr, err := IP4AddrFromAddrPort(local)
	if err != nil {
		return DynamicTableInfo{}, err
	}
	remoteAddr, err := IP4AddrFromAddrPort(remote)
	if err != nil {
		return DynamicTableInfo{}, err
	}

	conn := IP4Conn{
		Local:  localAddr,
		Remote: remoteAddr,
	}

	var info DynamicTableInfo
	if err := ap.dynamicTableInfo.Lookup(conn, &info); err != nil {
		return DynamicTableInfo{}, err
	}
	return info, nil
}

// ForgetConn removes the dynamic table entries for a specific connection.
func (ap *AttachedParser) ForgetConn(local, remote netip.AddrPort) error {
	localAddr, err := IP4AddrFromAddrPort(local)
	if err != nil {
		return err
	}
	remoteAddr, err := IP4AddrFromAddrPort(remote)
	if err != nil {
		return err
	}

	conn := IP4Conn{
		Local:  localAddr,
		Remote: remoteAddr,
	}

	var info DynamicTableInfo
	if err := ap.dynamicTableInfo.Lookup(conn, &info); err == nil {
		first := DynamicTableBase + info.Deleted
		for idx := first; idx < first+info.Count; idx++ {
			key := DynamicTableKey{Conn: conn, Idx: idx}
			_ = ap.dynamicTable.Delete(key)
		}
		_ = ap.dynamicTableInfo.Delete(conn)
	}

	_ = ap.continuedBlocks.Delete(conn)
	return nil
}

// Attach loads the HTTP/2 parser from a CollectionSpec, injects the DFA tables into .rodata,
// populates the static table map, and attaches the configured extension programs to targetProg.
func (p *Parser) Attach(spec *ebpf.CollectionSpec, targetProg *ebpf.Program) (*AttachedParser, error) {
	s2ts, a2as, err := p.CompileTables()
	if err != nil {
		return nil, err
	}

	specCopy := spec.Copy()

	// Inject DFA tables into .rodata
	if rodata, ok := specCopy.Maps[".rodata"]; ok && rodata != nil {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.NativeEndian, s2ts)
		_ = binary.Write(&buf, binary.NativeEndian, a2as)
		if len(rodata.Contents) > 0 && len(rodata.Contents[0].Value.([]byte)) >= buf.Len() {
			val := rodata.Contents[0].Value.([]byte)
			copy(val, buf.Bytes())
		}
	}

	// Determine required programs
	required := make(map[string]string)
	for msgBuf, fn := range p.parseFns {
		switch msgBuf {
		case beeper.MessageBufferMsg:
			required["parse_msg"] = fn
		case beeper.MessageBufferSkb:
			required["parse_skb"] = fn
		}
	}
	if p.matchedFn != "" {
		required["matched"] = p.matchedFn
	}
	for msgBuf, fn := range p.extractFns {
		switch msgBuf {
		case beeper.MessageBufferMsg:
			required["extract_match_msg"] = fn
		case beeper.MessageBufferSkb:
			required["extract_match_skb"] = fn
		}
	}
	if p.getDynamicTableEntryFn != "" {
		required["get_dt_entry"] = p.getDynamicTableEntryFn
	}

	// Filter out unused programs
	for name, progSpec := range specCopy.Programs {
		fn, needed := required[name]
		if !needed {
			delete(specCopy.Programs, name)
			continue
		}
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = fn
	}

	coll, err := ebpf.NewCollection(specCopy)
	if err != nil {
		return nil, &beeper.ErrBpf{Err: fmt.Errorf("load http2 collection: %w", err)}
	}

	// Populate static table
	staticTableMap, ok := coll.Maps["static_table"]
	if !ok {
		coll.Close()
		return nil, &beeper.ErrBpf{Err: fmt.Errorf("static_table map not found")}
	}

	stEntries, err := p.BuildStaticTableEntries()
	if err != nil {
		coll.Close()
		return nil, err
	}

	for idx, field := range stEntries {
		if err := staticTableMap.Put(idx, field); err != nil {
			coll.Close()
			return nil, &beeper.ErrBpf{Err: fmt.Errorf("populate static_table[%d]: %w", idx, err)}
		}
	}

	if err := staticTableMap.Freeze(); err != nil {
		coll.Close()
		return nil, &beeper.ErrBpf{Err: fmt.Errorf("freeze static_table: %w", err)}
	}

	var links []link.Link
	for name := range required {
		if prog, ok := coll.Programs[name]; ok {
			l, err := link.AttachTracing(link.TracingOptions{
				Program: prog,
			})
			if err != nil {
				coll.Close()
				return nil, &beeper.ErrBpf{Err: fmt.Errorf("attach %s: %w", name, err)}
			}
			links = append(links, l)
		}
	}

	return &AttachedParser{
		dynamicTableInfo: coll.Maps["dynamic_table_info"],
		dynamicTable:     coll.Maps["dynamic_table"],
		continuedBlocks:  coll.Maps["continued_blocks"],
		links:            links,
		coll:             coll,
	}, nil
}
