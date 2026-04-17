// Package mldsa implements ML-DSA (Module-Lattice Digital Signature Algorithm)
// as specified in FIPS 204.
//
// ML-DSA is a post-quantum digital signature scheme standardized by NIST.
// This package supports three security levels:
//   - ML-DSA-44: NIST security level 2 (comparable to AES-128)
//   - ML-DSA-65: NIST security level 3 (comparable to AES-192)
//   - ML-DSA-87: NIST security level 5 (comparable to AES-256)
//
// Basic usage:
//
//	key, err := mldsa.GenerateKey65(rand.Reader)
//	if err != nil {
//	    // handle error
//	}
//	sig, err := key.Sign(rand.Reader, message, nil)
//	if err != nil {
//	    // handle error
//	}
//	valid := key.PublicKey().Verify(sig, message, nil)
package mldsa

import "crypto"

// Global ML-DSA constants from FIPS 204.
const (
	// N is the number of coefficients in polynomials.
	N = 256

	// Q is the modulus: Q = 2^23 - 2^13 + 1 = 8380417
	Q = 8380417

	// D is the number of dropped bits from t.
	D = 13

	// SeedSize is the size of the random seed used for key generation.
	SeedSize = 32
)

// Derived constants.
const (
	QMinus1Div2 = (Q - 1) / 2
)

// Security level specific constants.
const (
	// gamma2 values for different modes
	Gamma2QMinus1Div88 = (Q - 1) / 88 // ML-DSA-44
	Gamma2QMinus1Div32 = (Q - 1) / 32 // ML-DSA-65, ML-DSA-87

	// gamma1 values (coefficient range of y)
	Gamma1Bits17 = 17
	Gamma1Bits19 = 19
	Gamma1Pow17  = 1 << Gamma1Bits17 // ML-DSA-44
	Gamma1Pow19  = 1 << Gamma1Bits19 // ML-DSA-65, ML-DSA-87

	// eta values (private key coefficient range)
	Eta2 = 2 // ML-DSA-44, ML-DSA-87
	Eta4 = 4 // ML-DSA-65

	// tau values (number of ±1s in challenge polynomial)
	Tau39 = 39 // ML-DSA-44
	Tau49 = 49 // ML-DSA-65
	Tau60 = 60 // ML-DSA-87

	// omega values (max number of 1s in hint)
	Omega80 = 80 // ML-DSA-44
	Omega55 = 55 // ML-DSA-65
	Omega75 = 75 // ML-DSA-87

	// lambda values (collision strength of c-tilde)
	Lambda128 = 128 // ML-DSA-44
	Lambda192 = 192 // ML-DSA-65
	Lambda256 = 256 // ML-DSA-87
)

// ML-DSA-44 parameters.
const (
	K44 = 4
	L44 = 4

	Beta44 = Eta2 * Tau39

	PublicKeySize44  = 32 + K44*N*10/8
	PrivateKeySize44 = 32 + 32 + 64 + (K44+L44)*N*3/8 + K44*N*13/8
	SignatureSize44  = Lambda128/4 + L44*N*18/8 + Omega80 + K44
)

// ML-DSA-65 parameters.
const (
	K65 = 6
	L65 = 5

	Beta65 = Eta4 * Tau49

	PublicKeySize65  = 32 + K65*N*10/8
	PrivateKeySize65 = 32 + 32 + 64 + (K65+L65)*N*4/8 + K65*N*13/8
	SignatureSize65  = Lambda192/4 + L65*N*20/8 + Omega55 + K65
)

// ML-DSA-87 parameters.
const (
	K87 = 8
	L87 = 7

	Beta87 = Eta2 * Tau60

	PublicKeySize87  = 32 + K87*N*10/8
	PrivateKeySize87 = 32 + 32 + 64 + (K87+L87)*N*3/8 + K87*N*13/8
	SignatureSize87  = Lambda256/4 + L87*N*20/8 + Omega75 + K87
)

// Encoding size constants (bytes per polynomial).
const (
	EncodingSize3  = N * 3 / 8  // eta=2 packed
	EncodingSize4  = N * 4 / 8  // eta=4 packed or 4-bit w1
	EncodingSize6  = N * 6 / 8  // 6-bit w1 for ML-DSA-44
	EncodingSize10 = N * 10 / 8 // t1 packed
	EncodingSize13 = N * 13 / 8 // t0 packed
	EncodingSize18 = N * 18 / 8 // z for gamma1=2^17
	EncodingSize20 = N * 20 / 8 // z for gamma1=2^19
)

// SignerOpts implements crypto.SignerOpts for ML-DSA signing operations.
// It allows specifying an optional context string for domain separation.
type SignerOpts struct {
	// Context is an optional context string for domain separation (max 255 bytes).
	// If nil, no context is used.
	Context []byte
}

// HashFunc returns 0 to indicate that ML-DSA does not use pre-hashing.
// ML-DSA signs messages directly rather than message digests.
func (opts *SignerOpts) HashFunc() crypto.Hash {
	return 0
}

// Compile-time interface assertions for crypto.Signer.
var (
	_ crypto.Signer = (*PrivateKey44)(nil)
	_ crypto.Signer = (*PrivateKey65)(nil)
	_ crypto.Signer = (*PrivateKey87)(nil)
)
