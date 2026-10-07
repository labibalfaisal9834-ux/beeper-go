package http2

import (
	"golang.org/x/net/http2/hpack"
)

// HuffmanEncode encodes src using HPACK Huffman coding and appends it to dst.
func HuffmanEncode(src []byte, dst *[]byte) error {
	*dst = hpack.AppendHuffmanString(*dst, string(src))
	return nil
}

// HuffmanDecode decodes Huffman-encoded bytes into plain text.
func HuffmanDecode(src []byte) ([]byte, error) {
	str, err := hpack.HuffmanDecodeToString(src)
	if err != nil {
		return nil, err
	}
	return []byte(str), nil
}
