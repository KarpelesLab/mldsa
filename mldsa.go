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
	// n is the number of coefficients in polynomials.
	n = 256

	// q is the modulus: q = 2^23 - 2^13 + 1 = 8380417
	q = 8380417

	// d is the number of dropped bits from t.
	d = 13

	// SeedSize is the size of the random seed used for key generation.
	SeedSize = 32
)

// Derived constants.
const (
	qMinus1Div2 = (q - 1) / 2
)

// Security level specific constants.
const (
	// gamma2 values for different modes
	gamma2QMinus1Div88 = (q - 1) / 88 // ML-DSA-44
	gamma2QMinus1Div32 = (q - 1) / 32 // ML-DSA-65, ML-DSA-87

	// gamma1 values (coefficient range of y)
	gamma1Bits17 = 17
	gamma1Bits19 = 19
	gamma1Pow17  = 1 << gamma1Bits17 // ML-DSA-44
	gamma1Pow19  = 1 << gamma1Bits19 // ML-DSA-65, ML-DSA-87

	// eta values (private key coefficient range)
	eta2 = 2 // ML-DSA-44, ML-DSA-87
	eta4 = 4 // ML-DSA-65

	// tau values (number of ±1s in challenge polynomial)
	tau39 = 39 // ML-DSA-44
	tau49 = 49 // ML-DSA-65
	tau60 = 60 // ML-DSA-87

	// omega values (max number of 1s in hint)
	omega80 = 80 // ML-DSA-44
	omega55 = 55 // ML-DSA-65
	omega75 = 75 // ML-DSA-87

	// lambda values (collision strength of c-tilde)
	lambda128 = 128 // ML-DSA-44
	lambda192 = 192 // ML-DSA-65
	lambda256 = 256 // ML-DSA-87
)

// ML-DSA-44 parameters.
const (
	k44 = 4
	l44 = 4

	beta44 = eta2 * tau39

	PublicKeySize44  = 32 + k44*n*10/8
	PrivateKeySize44 = 32 + 32 + 64 + (k44+l44)*n*3/8 + k44*n*13/8
	SignatureSize44  = lambda128/4 + l44*n*18/8 + omega80 + k44
)

// ML-DSA-65 parameters.
const (
	k65 = 6
	l65 = 5

	beta65 = eta4 * tau49

	PublicKeySize65  = 32 + k65*n*10/8
	PrivateKeySize65 = 32 + 32 + 64 + (k65+l65)*n*4/8 + k65*n*13/8
	SignatureSize65  = lambda192/4 + l65*n*20/8 + omega55 + k65
)

// ML-DSA-87 parameters.
const (
	k87 = 8
	l87 = 7

	beta87 = eta2 * tau60

	PublicKeySize87  = 32 + k87*n*10/8
	PrivateKeySize87 = 32 + 32 + 64 + (k87+l87)*n*3/8 + k87*n*13/8
	SignatureSize87  = lambda256/4 + l87*n*20/8 + omega75 + k87
)

// Encoding size constants (bytes per polynomial).
const (
	encodingSize3  = n * 3 / 8  // eta=2 packed
	encodingSize4  = n * 4 / 8  // eta=4 packed or 4-bit w1
	encodingSize6  = n * 6 / 8  // 6-bit w1 for ML-DSA-44
	encodingSize10 = n * 10 / 8 // t1 packed
	encodingSize13 = n * 13 / 8 // t0 packed
	encodingSize18 = n * 18 / 8 // z for gamma1=2^17
	encodingSize20 = n * 20 / 8 // z for gamma1=2^19
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
