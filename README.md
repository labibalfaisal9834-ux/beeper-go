# Beeper (Go): Application-Layer Parsing in eBPF

Beeper (BEEline's ParsER) is an application-layer parser for Linux eBPF in Go. It allows you to process L7 protocols directly in the kernel, which can accelerate user-space applications significantly. It achieves this by constructing a DFA in user space and injecting it into eBPF `freplace` programs, reducing parsing complexity to an eBPF-compatible level. With Beeper, you can monitor application-layer traffic, redirect it based on its payload, or respond to it directly from the kernel without copying payloads to user space.

| Protocol     | Status       | Minimal Kernel Version |
| :----------- | :----------- | :--------------------- |
| **HTTP/1.1** | ✅ Supported | 6.8                    |
| **HTTP/2**   | ✅ Supported | 6.8                    |
| **RESP2**    | 🚧 WIP       | —                      |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         USER SPACE                          │
│                                                             │
│  1. Configure Headers       2. DFA Compilation              │
│     (e.g. :path, :method,       Pattern -> DFA Engine       │
│      User-Agent, etc.)          (Case-insensitive, wildcards,│
│                                  HPACK static/dynamic tries)│
│                                                             │
│  3. Attach to Target eBPF Program                           │
│     - Open BPF Object Spec with cilium/ebpf                 │
│     - Inject DFA Table (s2ts) & Actions (a2as) into .rodata │
│     - For HTTP/2: Populate & Freeze Static Table Map        │
│     - freplace Attach to target prog FD (parse, extract)    │
└──────────────────────────────┬──────────────────────────────┘
                               │ eBPF freplace link attachment
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE                         │
│                                                             │
│  Target BPF Hook (sk_msg / sk_skb verdict)                  │
│     │                                                       │
│     ├──► freplace stub: parse_http1() / parse_http2()       │
│     │    • Walks packet data byte-by-byte through DFA       │
│     │    • Updates HTTP/2 HPACK dynamic table across frames │
│     │    • Records capture bounds (idx, len, in_msg, huff)  │
│     │                                                       │
│     └──► freplace stub: extract_match() / get_dt_entry()    │
│          • Resolves matches in-place from packet or tables  │
└──────────────────────────────┘
```

---

## Usage

### 1. Go User-Space Setup

Configure desired headers to capture and attach the parser to your target BPF program using `cilium/ebpf`:

```go
package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/lerboe/beeper-go/pkg/beeper"
	"github.com/lerboe/beeper-go/pkg/beeper/http2"
)

func main() {
	// Create an HTTP/2 parser instance
	h2 := http2.New()
	pathMid, err := h2.CaptureHdrString(beeper.PseudoHeaderPath.AsStr())
	if err != nil {
		log.Fatalf("failed to capture :path: %v", err)
	}
	contentLengthMid, err := h2.CaptureHdrString("content-length")
	if err != nil {
		log.Fatalf("failed to capture content-length: %v", err)
	}

	h2.ParseFn("parse_http2", beeper.MessageBufferMsg).
		ExtractFn("extract_http2_match", beeper.MessageBufferMsg)

	// Load your BPF collection spec and target program (e.g. sk_msg verdict)
	// targetSpec, _ := ebpf.LoadCollectionSpec("path/to/target.o")
	// targetColl, _ := ebpf.NewCollection(targetSpec)
	// h2Spec, _ := ebpf.LoadCollectionSpec("bpf/http2_parser.o")
	// targetProg := targetColl.Programs["msg_verdict"]

	// attached, err := h2.Attach(h2Spec, targetProg)
	// if err != nil {
	//     log.Fatalf("failed to attach parser: %v", err)
	// }
	// defer attached.Close()

	_ = pathMid
	_ = contentLengthMid
}
```

### 2. Kernel eBPF C Code

Include Beeper headers, define the replacement stubs, and invoke parsing:

```c
#include "beeper/http2.h"

// Define Beeper replacement stubs
BEEPER_EXTRACT_MATCH_MSG(extract_http2_match)
BEEPER_HTTP2_PARSE_MSG(parse_http2)

// Match IDs passed from user space
volatile const u8 h2_path_mid;
volatile const u8 h2_content_length_mid;

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    struct http_parse_res pres = { 0 };
    struct http2_frame frame = { 0 };
    int msg_len = parse_http2(msg, &pres, &frame);
    if (msg_len >= 0) {
        struct bytes path = { 0 };
        if (extract_http2_match(msg, &pres, h2_path_mid, &path) == 0) {
            // path.ptr points to the captured path (may be Huffman-encoded)
        }
    }

    return SK_PASS;
}
```

---

## Package Layout

- **`pkg/beeper`**: Core types (`MessageBuffer`, `MatchId`, `StateId`, `PseudoHeaderName`, errors) and generic DFA engine (`DFA`, `DFABuilder`).
- **`pkg/beeper/http1`**: HTTP/1.1 parsing engine, status line matching, HTTP/2 preface upgrade detection, and `.rodata` DFA table compiler.
- **`pkg/beeper/http2`**: HTTP/2 & HPACK parsing engine, RFC 7541 Huffman codec, 61-entry static table generator, and dynamic table manager.
- **`include/beeper/`**: C header files ([beeper.h](include/beeper/beeper.h), [http.h](include/beeper/http.h), [http1.h](include/beeper/http1.h), [http2.h](include/beeper/http2.h), [resp2.h](include/beeper/resp2.h)).
- **`bpf/`**: Kernel eBPF C programs (`http1_parser.bpf.c`, `http2_parser.bpf.c`, `monitor.bpf.c`).
- **`testutil/`**: Test echo server and test harness.
- **`example/`**: Example HTTP monitoring proxy.

---

## Testing & Verification

Run tests with Go's data race detector:

```bash
go test -v -race ./...
```

Run static analysis:

```bash
go vet ./...
```

---

## Citation

If you use this library to conduct research, please cite the original Beeper research paper:

```bibtex
@misc{beeline,
      title={Enforcing Application-Layer Policies in eBPF},
      author={Laurin Brandner and Ayush Mishra and Sebastiano Miano and Aurojit Panda and Gianni Antichi and Laurent Vanbever},
      year={2026},
      eprint={2605.31084},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2605.31084},
}
```

## Verification Checklist for Linux Kernel eBPF Execution

When running the eBPF integration on Linux (minimum kernel 6.8 with CONFIG_BPF_JIT=y and CONFIG_BPF_SYSCALL=y):

### Compile BPF objects:

```bash
clang -O2 -target bpf -g -I include/ -c bpf/http1_parser.bpf.c -o bpf/http1_parser.o
clang -O2 -target bpf -g -I include/ -c bpf/http2_parser.bpf.c -o bpf/http2_parser.o
clang -O2 -target bpf -g -I include/ -c bpf/monitor.bpf.c -o bpf/monitor.o
```

### Run tests with root / CAP_BPF & CAP_NET_ADMIN:

```bash
sudo go test -v ./...
```

### Run the example L7 monitoring server:

```bash
sudo go run example/main.go
```

## License

GPL-3.0
