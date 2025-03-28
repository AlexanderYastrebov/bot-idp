package main

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func BenchmarkSha256(b *testing.B) {
	h := sha256.New()
	block := make([]byte, 32)
	nonce := uint64(0)
	for range b.N {
		nonce++
		h.Write(block)
		binary.Write(h, binary.BigEndian, nonce)
		_ = h.Sum(nil)
	}
}
