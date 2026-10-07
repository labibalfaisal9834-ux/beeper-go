package http1

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lerboe/beeper-go/pkg/beeper"
)

// AttachedParser represents a loaded and attached HTTP/1.1 BPF parser.
type AttachedParser struct {
	links []link.Link
	coll  *ebpf.Collection
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

// Attach loads the HTTP/1.1 parser from a CollectionSpec, injects the DFA tables into .rodata,
// and attaches the configured extension programs to targetProg.
func (p *Parser) Attach(spec *ebpf.CollectionSpec, targetProg *ebpf.Program) (*AttachedParser, error) {
	parser := p.DoneOnHdrEnd()

	s2ts, a2as, err := parser.CompileTables()
	if err != nil {
		return nil, err
	}

	specCopy := spec.Copy()

	// Inject tables into .rodata map if present
	if rodata, ok := specCopy.Maps[".rodata"]; ok && rodata != nil {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.NativeEndian, s2ts)
		_ = binary.Write(&buf, binary.NativeEndian, a2as)
		if len(rodata.Contents) > 0 && len(rodata.Contents[0].Value.([]byte)) >= buf.Len() {
			val := rodata.Contents[0].Value.([]byte)
			copy(val, buf.Bytes())
		}
	}

	// Determine required programs and configure attach targets
	required := make(map[string]string)
	for msgBuf, fn := range parser.parseFns {
		switch msgBuf {
		case beeper.MessageBufferMsg:
			required["parse_msg"] = fn
		case beeper.MessageBufferSkb:
			required["parse_skb"] = fn
		}
	}
	if parser.matchedFn != "" {
		required["matched"] = parser.matchedFn
	}
	for msgBuf, fn := range parser.extractFns {
		switch msgBuf {
		case beeper.MessageBufferMsg:
			required["extract_match_msg"] = fn
		case beeper.MessageBufferSkb:
			required["extract_match_skb"] = fn
		}
	}

	// Filter out unused programs (equivalent to set_autoload(false))
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
		return nil, &beeper.ErrBpf{Err: fmt.Errorf("load http1 collection: %w", err)}
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
		links: links,
		coll:  coll,
	}, nil
}
