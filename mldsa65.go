package mldsa

import (
	"crypto"
	"crypto/sha3"
	"errors"
	"io"
)

// PrivateKey65 is the private key for ML-DSA-65.
type PrivateKey65 struct {
	rho [32]byte              // Public seed
	key [32]byte              // Private seed for signing
	tr  [64]byte              // H(pk)
	s1  [l65]ringElement      // Secret vector
	s2  [k65]ringElement      // Secret vector
	t0  [k65]ringElement      // Low bits of t
	a   [k65 * l65]nttElement // Matrix A in NTT form
}

// PublicKey65 is the public key for ML-DSA-65.
type PublicKey65 struct {
	rho [32]byte              // Public seed
	t1  [k65]ringElement      // High bits of t
	tr  [64]byte              // H(pk)
	a   [k65 * l65]nttElement // Matrix A in NTT form
}

// Key65 is a key pair for ML-DSA-65, containing both private and public components.
type Key65 struct {
	PrivateKey65
	seed [32]byte         // Original seed
	t1   [k65]ringElement // Public key component
}

// GenerateKey65 generates a new ML-DSA-65 key pair.
func GenerateKey65(rand io.Reader) (*Key65, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	return NewKey65(seed[:])
}

// NewKey65 creates a key pair from a seed.
func NewKey65(seed []byte) (*Key65, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mldsa: invalid seed length")
	}

	key := &Key65{}
	copy(key.seed[:], seed)
	key.generate()
	return key, nil
}

// generate derives all key components from the seed.
func (key *Key65) generate() {
	// Expand seed: SHAKE256(seed || k || l)
	h := sha3.NewSHAKE256()
	h.Write(key.seed[:])
	h.Write([]byte{k65, l65})

	var expanded [128]byte
	h.Read(expanded[:])

	copy(key.rho[:], expanded[:32])
	rho1 := expanded[32:96]
	copy(key.key[:], expanded[96:128])

	// Generate secret vectors s1, s2
	for i := 0; i < l65; i++ {
		key.s1[i] = sampleBoundedPoly(rho1, eta4, uint16(i))
	}
	for i := 0; i < k65; i++ {
		key.s2[i] = sampleBoundedPoly(rho1, eta4, uint16(l65+i))
	}

	// Generate matrix A in NTT form
	for i := 0; i < k65; i++ {
		for j := 0; j < l65; j++ {
			key.a[i*l65+j] = sampleNTTPoly(key.rho[:], byte(j), byte(i))
		}
	}

	// Compute t = A*s1 + s2
	var s1NTT [l65]nttElement
	for i := 0; i < l65; i++ {
		s1NTT[i] = ntt(key.s1[i])
	}

	var t [k65]ringElement
	for i := 0; i < k65; i++ {
		var acc nttElement
		for j := 0; j < l65; j++ {
			acc = polyAdd(acc, nttMul(key.a[i*l65+j], s1NTT[j]))
		}
		t[i] = polyAdd(invNTT(acc), key.s2[i])

		// Power2Round: t = t1*2^d + t0
		for j := 0; j < n; j++ {
			key.t1[i][j], key.t0[i][j] = power2Round(t[i][j])
		}
	}

	// Compute tr = H(pk)
	pkBytes := key.publicKeyBytes()
	h.Reset()
	h.Write(pkBytes)
	h.Read(key.tr[:])
}

// publicKeyBytes returns the encoded public key.
func (key *Key65) publicKeyBytes() []byte {
	b := make([]byte, PublicKeySize65)
	copy(b[:32], key.rho[:])
	offset := 32
	for i := 0; i < k65; i++ {
		packed := packT1(key.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
	}
	return b
}

// PublicKey returns the public key for this key pair.
func (key *Key65) PublicKey() *PublicKey65 {
	return &PublicKey65{
		rho: key.rho,
		t1:  key.t1,
		tr:  key.tr,
		a:   key.a,
	}
}

// Bytes returns the seed (32 bytes).
func (key *Key65) Bytes() []byte {
	b := make([]byte, SeedSize)
	copy(b, key.seed[:])
	return b
}

// PrivateKeyBytes returns the full encoded private key.
func (key *Key65) PrivateKeyBytes() []byte {
	return key.PrivateKey65.Bytes()
}

// Bytes returns the encoded private key.
func (sk *PrivateKey65) Bytes() []byte {
	b := make([]byte, PrivateKeySize65)
	copy(b[:32], sk.rho[:])
	copy(b[32:64], sk.key[:])
	copy(b[64:128], sk.tr[:])

	offset := 128
	for i := 0; i < l65; i++ {
		packed := packEta4(sk.s1[i])
		copy(b[offset:], packed)
		offset += encodingSize4
	}
	for i := 0; i < k65; i++ {
		packed := packEta4(sk.s2[i])
		copy(b[offset:], packed)
		offset += encodingSize4
	}
	for i := 0; i < k65; i++ {
		packed := packT0(sk.t0[i])
		copy(b[offset:], packed)
		offset += encodingSize13
	}
	return b
}

// Bytes returns the encoded public key.
func (pk *PublicKey65) Bytes() []byte {
	b := make([]byte, PublicKeySize65)
	copy(b[:32], pk.rho[:])
	offset := 32
	for i := 0; i < k65; i++ {
		packed := packT1(pk.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
	}
	return b
}

// Equal reports whether pk and other are the same public key.
func (pk *PublicKey65) Equal(other crypto.PublicKey) bool {
	o, ok := other.(*PublicKey65)
	if !ok {
		return false
	}
	return pk.rho == o.rho && pk.t1 == o.t1
}

// NewPublicKey65 parses an encoded public key.
func NewPublicKey65(b []byte) (*PublicKey65, error) {
	if len(b) != PublicKeySize65 {
		return nil, errors.New("mldsa: invalid public key length")
	}

	pk := &PublicKey65{}
	copy(pk.rho[:], b[:32])

	offset := 32
	for i := 0; i < k65; i++ {
		pk.t1[i] = unpackT1(b[offset : offset+encodingSize10])
		offset += encodingSize10
	}

	// Generate A matrix
	for i := 0; i < k65; i++ {
		for j := 0; j < l65; j++ {
			pk.a[i*l65+j] = sampleNTTPoly(pk.rho[:], byte(j), byte(i))
		}
	}

	// Compute tr = H(pk)
	h := sha3.NewSHAKE256()
	h.Write(b)
	h.Read(pk.tr[:])

	return pk, nil
}

// NewPrivateKey65 parses an encoded private key.
func NewPrivateKey65(b []byte) (*PrivateKey65, error) {
	if len(b) != PrivateKeySize65 {
		return nil, errors.New("mldsa: invalid private key length")
	}

	sk := &PrivateKey65{}
	copy(sk.rho[:], b[:32])
	copy(sk.key[:], b[32:64])
	copy(sk.tr[:], b[64:128])

	offset := 128
	var err error
	for i := 0; i < l65; i++ {
		sk.s1[i], err = unpackEta4(b[offset : offset+encodingSize4])
		if err != nil {
			return nil, err
		}
		offset += encodingSize4
	}
	for i := 0; i < k65; i++ {
		sk.s2[i], err = unpackEta4(b[offset : offset+encodingSize4])
		if err != nil {
			return nil, err
		}
		offset += encodingSize4
	}
	for i := 0; i < k65; i++ {
		sk.t0[i] = unpackT0(b[offset : offset+encodingSize13])
		offset += encodingSize13
	}

	// Generate A matrix
	for i := 0; i < k65; i++ {
		for j := 0; j < l65; j++ {
			sk.a[i*l65+j] = sampleNTTPoly(sk.rho[:], byte(j), byte(i))
		}
	}

	return sk, nil
}

// Public returns the public key corresponding to this private key.
// This implements the crypto.Signer interface.
func (sk *PrivateKey65) Public() crypto.PublicKey {
	// Reconstruct public key from private key components
	pk := &PublicKey65{
		rho: sk.rho,
		tr:  sk.tr,
		a:   sk.a,
	}
	// Compute t1 from s1, s2 via A*s1 + s2, then take high bits
	var s1NTT [l65]nttElement
	for i := 0; i < l65; i++ {
		s1NTT[i] = ntt(sk.s1[i])
	}
	for i := 0; i < k65; i++ {
		var acc nttElement
		for j := 0; j < l65; j++ {
			acc = polyAdd(acc, nttMul(sk.a[i*l65+j], s1NTT[j]))
		}
		t := polyAdd(invNTT(acc), sk.s2[i])
		for j := 0; j < n; j++ {
			pk.t1[i][j], _ = power2Round(t[j])
		}
	}
	return pk
}

// Sign signs digest with the private key.
// This implements the crypto.Signer interface.
//
// For ML-DSA, the digest is the message to be signed (not a hash).
// If opts is *SignerOpts, its Context field is used for domain separation.
// If opts is nil or not *SignerOpts, no context is used.
func (sk *PrivateKey65) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return sk.SignMessage(rand, digest, opts)
}

// SignMessage signs msg with the private key.
// This implements the crypto.MessageSigner interface.
//
// If opts is *SignerOpts, its Context field is used for domain separation.
// If opts is nil or not *SignerOpts, no context is used.
// Returns an error if opts specifies a hash function, as ML-DSA signs messages directly.
func (sk *PrivateKey65) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("mldsa: cannot sign pre-hashed messages")
	}
	var context []byte
	if o, ok := opts.(*SignerOpts); ok && o != nil {
		context = o.Context
	}
	return sk.SignWithContext(rand, msg, context)
}

// SignWithContext signs a message with an optional context string.
// Context must be at most 255 bytes.
func (sk *PrivateKey65) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error) {
	if len(context) > 255 {
		return nil, errors.New("mldsa: context too long")
	}

	var rnd [32]byte
	if _, err := io.ReadFull(rand, rnd[:]); err != nil {
		return nil, err
	}

	// M' = 0 || len(ctx) || ctx || msg
	mPrime := make([]byte, 2+len(context)+len(message))
	mPrime[0] = 0
	mPrime[1] = byte(len(context))
	copy(mPrime[2:], context)
	copy(mPrime[2+len(context):], message)

	return sk.signInternal(rnd[:], mPrime)
}

// signInternal implements ML-DSA.Sign_internal (FIPS 204 Algorithm 7).
// mPrime is the message M' (for external signing: 0 || len(ctx) || ctx || msg)
func (sk *PrivateKey65) signInternal(rnd, mPrime []byte) ([]byte, error) {
	// Compute mu = H(tr || M')
	h := sha3.NewSHAKE256()
	h.Write(sk.tr[:])
	h.Write(mPrime)

	var mu [64]byte
	h.Read(mu[:])

	// Compute rho' = H(key || rnd || mu)
	h.Reset()
	h.Write(sk.key[:])
	h.Write(rnd)
	h.Write(mu[:])

	var rhoPrime [64]byte
	h.Read(rhoPrime[:])

	// Precompute NTT of secret vectors
	var s1NTT [l65]nttElement
	var s2NTT [k65]nttElement
	var t0NTT [k65]nttElement
	for i := 0; i < l65; i++ {
		s1NTT[i] = ntt(sk.s1[i])
	}
	for i := 0; i < k65; i++ {
		s2NTT[i] = ntt(sk.s2[i])
		t0NTT[i] = ntt(sk.t0[i])
	}

	// Rejection sampling loop
	var seedBuf [66]byte
	copy(seedBuf[:64], rhoPrime[:])

	for kappa := uint16(0); ; kappa += l65 {
		// Generate masking vector y
		var y [l65]ringElement
		for i := 0; i < l65; i++ {
			seedBuf[64] = byte(kappa + uint16(i))
			seedBuf[65] = byte((kappa + uint16(i)) >> 8)
			y[i] = expandMask(seedBuf[:], gamma1Bits19)
		}

		// Compute w = A*y
		var yNTT [l65]nttElement
		for i := 0; i < l65; i++ {
			yNTT[i] = ntt(y[i])
		}

		var w [k65]ringElement
		var w1 [k65]ringElement
		for i := 0; i < k65; i++ {
			var acc nttElement
			for j := 0; j < l65; j++ {
				acc = polyAdd(acc, nttMul(sk.a[i*l65+j], yNTT[j]))
			}
			w[i] = invNTT(acc)

			// Compute w1 = HighBits(w)
			for j := 0; j < n; j++ {
				w1[i][j] = fieldElement(highBits(w[i][j], gamma2QMinus1Div32))
			}
		}

		// Compute challenge hash c~ = H(mu || w1)
		h.Reset()
		h.Write(mu[:])
		for i := 0; i < k65; i++ {
			h.Write(packW1_4(w1[i]))
		}
		var cTilde [lambda192 / 4]byte
		h.Read(cTilde[:])

		// Sample challenge polynomial c
		c := sampleChallenge(cTilde[:], tau49)
		cNTT := ntt(c)

		// Compute z = y + c*s1
		var z [l65]ringElement
		for i := 0; i < l65; i++ {
			cs1 := invNTT(nttMul(cNTT, s1NTT[i]))
			z[i] = polyAdd(y[i], cs1)
		}

		// Check ||z||_inf < gamma1 - beta
		if vectorInfinityNorm(z[:]) >= gamma1Pow19-beta65 {
			continue
		}

		// Compute r0 = LowBits(w - c*s2)
		var r0 [k65][n]int32
		for i := 0; i < k65; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				_, r0[i][j] = decompose(fieldSub(w[i][j], cs2[j]), gamma2QMinus1Div32)
			}
		}

		// Check ||r0||_inf < gamma2 - beta
		if vectorInfinityNormSigned(r0[:]) >= int32(gamma2QMinus1Div32-beta65) {
			continue
		}

		// Compute ct0
		var ct0 [k65]ringElement
		for i := 0; i < k65; i++ {
			ct0[i] = invNTT(nttMul(cNTT, t0NTT[i]))
		}

		// Check ||ct0||_inf < gamma2
		if vectorInfinityNorm(ct0[:]) >= gamma2QMinus1Div32 {
			continue
		}

		// Compute hints
		var hints [k65]ringElement
		for i := 0; i < k65; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				// r = w - cs2, z = ct0
				r := fieldSub(w[i][j], cs2[j])
				hints[i][j] = makeHint(ct0[i][j], r, gamma2QMinus1Div32)
			}
		}

		// Check number of hints <= omega
		if countOnes(hints[:]) > omega55 {
			continue
		}

		// Encode signature
		sig := make([]byte, SignatureSize65)
		copy(sig[:len(cTilde)], cTilde[:])
		offset := len(cTilde)
		for i := 0; i < l65; i++ {
			packed := packZ19(z[i])
			copy(sig[offset:], packed)
			offset += encodingSize20
		}
		hintPacked := packHint(hints[:], omega55)
		copy(sig[offset:], hintPacked)

		return sig, nil
	}
}

// Verify checks the signature on message with optional context.
func (pk *PublicKey65) Verify(sig, message, context []byte) bool {
	if len(sig) != SignatureSize65 {
		return false
	}
	if len(context) > 255 {
		return false
	}

	// M' = 0 || len(ctx) || ctx || msg
	mPrime := make([]byte, 2+len(context)+len(message))
	mPrime[0] = 0
	mPrime[1] = byte(len(context))
	copy(mPrime[2:], context)
	copy(mPrime[2+len(context):], message)

	return pk.verifyInternal(sig, mPrime)
}

// verifyInternal implements ML-DSA.Verify_internal (FIPS 204 Algorithm 8).
// mPrime is the message M' (for external verification: 0 || len(ctx) || ctx || msg)
func (pk *PublicKey65) verifyInternal(sig, mPrime []byte) bool {
	// Compute mu = H(tr || M')
	h := sha3.NewSHAKE256()
	h.Write(pk.tr[:])
	h.Write(mPrime)

	var mu [64]byte
	h.Read(mu[:])

	// Decode signature
	cTilde := sig[:lambda192/4]
	offset := lambda192 / 4

	var z [l65]ringElement
	for i := 0; i < l65; i++ {
		z[i] = unpackZ19Sig(sig[offset : offset+encodingSize20])
		offset += encodingSize20
	}

	// Check ||z||_inf < gamma1 - beta
	if vectorInfinityNorm(z[:]) >= gamma1Pow19-beta65 {
		return false
	}

	var hints [k65]ringElement
	if !unpackHint(sig[offset:], hints[:], omega55) {
		return false
	}

	// Sample challenge
	c := sampleChallenge(cTilde, tau49)
	cNTT := ntt(c)

	// Compute NTT of z
	var zNTT [l65]nttElement
	for i := 0; i < l65; i++ {
		zNTT[i] = ntt(z[i])
	}

	// Compute t1*2^d in NTT form
	var t1NTT [k65]nttElement
	for i := 0; i < k65; i++ {
		var t1Scaled ringElement
		for j := 0; j < n; j++ {
			t1Scaled[j] = pk.t1[i][j] << d
		}
		t1NTT[i] = ntt(t1Scaled)
	}

	// Compute w' = A*z - c*t1*2^d
	var w1 [k65]ringElement
	h.Reset()
	h.Write(mu[:])

	for i := 0; i < k65; i++ {
		var acc nttElement
		for j := 0; j < l65; j++ {
			acc = polyAdd(acc, nttMul(pk.a[i*l65+j], zNTT[j]))
		}
		ct1 := nttMul(cNTT, t1NTT[i])
		acc = polySub(acc, ct1)
		wApprox := invNTT(acc)

		// Use hints to recover w1
		for j := 0; j < n; j++ {
			w1[i][j] = useHint(hints[i][j], wApprox[j], gamma2QMinus1Div32)
		}

		h.Write(packW1_4(w1[i]))
	}

	// Verify c~ = H(mu || w1)
	var cTildeCheck [lambda192 / 4]byte
	h.Read(cTildeCheck[:])

	// Constant-time comparison
	var diff byte
	for i := range cTilde {
		diff |= cTilde[i] ^ cTildeCheck[i]
	}
	return diff == 0
}

// Sign signs digest with the key pair's private key.
// This implements the crypto.Signer interface.
func (key *Key65) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.PrivateKey65.Sign(rand, digest, opts)
}

// SignMessage signs msg with the key pair's private key.
// This implements the crypto.MessageSigner interface.
func (key *Key65) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.PrivateKey65.SignMessage(rand, msg, opts)
}

// SignWithContext signs a message with an optional context string using the key pair.
func (key *Key65) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error) {
	return key.PrivateKey65.SignWithContext(rand, message, context)
}
