//go:build go1.25

package mldsa

import "crypto"

// Compile-time interface assertions for crypto.MessageSigner (Go 1.25+).
var (
	_ crypto.MessageSigner = (*PrivateKey44)(nil)
	_ crypto.MessageSigner = (*PrivateKey65)(nil)
	_ crypto.MessageSigner = (*PrivateKey87)(nil)
)
