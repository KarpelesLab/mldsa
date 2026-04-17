package mldsa

import (
	"crypto"
	"crypto/sha3"
	"errors"
	"io"
)

// PrivateKey44 is the private key for ML-DSA-44.
type PrivateKey44 struct {
	rho [32]byte              // Public seed
	key [32]byte              // Private seed for signing
	tr  [64]byte              // H(pk)
	s1  [L44]RingElement      // Secret vector
	s2  [K44]RingElement      // Secret vector
	t0  [K44]RingElement      // Low bits of t
	a   [K44 * L44]NttElement // Matrix A in NTT form
}

// PublicKey44 is the public key for ML-DSA-44.
type PublicKey44 struct {
	rho [32]byte              // Public seed
	t1  [K44]RingElement      // High bits of t
	tr  [64]byte              // H(pk)
	a   [K44 * L44]NttElement // Matrix A in NTT form
}

// Key44 is a key pair for ML-DSA-44.
type Key44 struct {
	PrivateKey44
	seed [32]byte         // Original seed
	t1   [K44]RingElement // Public key component
}

// GenerateKey44 generates a new ML-DSA-44 key pair.
func GenerateKey44(rand io.Reader) (*Key44, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	return NewKey44(seed[:])
}

// NewKey44 creates a key pair from a seed.
func NewKey44(seed []byte) (*Key44, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mldsa: invalid seed length")
	}

	key := &Key44{}
	copy(key.seed[:], seed)
	key.generate()
	return key, nil
}

func (key *Key44) generate() {
	h := sha3.NewSHAKE256()
	h.Write(key.seed[:])
	h.Write([]byte{K44, L44})

	var expanded [128]byte
	h.Read(expanded[:])

	copy(key.rho[:], expanded[:32])
	rho1 := expanded[32:96]
	copy(key.key[:], expanded[96:128])

	for i := 0; i < L44; i++ {
		key.s1[i] = SampleBoundedPoly(rho1, Eta2, uint16(i))
	}
	for i := 0; i < K44; i++ {
		key.s2[i] = SampleBoundedPoly(rho1, Eta2, uint16(L44+i))
	}

	for i := 0; i < K44; i++ {
		for j := 0; j < L44; j++ {
			key.a[i*L44+j] = SampleNTTPoly(key.rho[:], byte(j), byte(i))
		}
	}

	var s1NTT [L44]NttElement
	for i := 0; i < L44; i++ {
		s1NTT[i] = NTT(key.s1[i])
	}

	var t [K44]RingElement
	for i := 0; i < K44; i++ {
		var acc NttElement
		for j := 0; j < L44; j++ {
			acc = PolyAdd(acc, NttMul(key.a[i*L44+j], s1NTT[j]))
		}
		t[i] = PolyAdd(InvNTT(acc), key.s2[i])

		for j := 0; j < N; j++ {
			key.t1[i][j], key.t0[i][j] = Power2Round(t[i][j])
		}
	}

	pkBytes := key.publicKeyBytes()
	h.Reset()
	h.Write(pkBytes)
	h.Read(key.tr[:])
}

func (key *Key44) publicKeyBytes() []byte {
	b := make([]byte, PublicKeySize44)
	copy(b[:32], key.rho[:])
	offset := 32
	for i := 0; i < K44; i++ {
		packed := PackT1(key.t1[i])
		copy(b[offset:], packed)
		offset += EncodingSize10
	}
	return b
}

// PublicKey returns the public key.
func (key *Key44) PublicKey() *PublicKey44 {
	return &PublicKey44{
		rho: key.rho,
		t1:  key.t1,
		tr:  key.tr,
		a:   key.a,
	}
}

// Bytes returns the seed.
func (key *Key44) Bytes() []byte {
	b := make([]byte, SeedSize)
	copy(b, key.seed[:])
	return b
}

// PrivateKeyBytes returns the full encoded private key.
func (key *Key44) PrivateKeyBytes() []byte {
	return key.PrivateKey44.Bytes()
}

// Bytes returns the encoded private key.
func (sk *PrivateKey44) Bytes() []byte {
	b := make([]byte, PrivateKeySize44)
	copy(b[:32], sk.rho[:])
	copy(b[32:64], sk.key[:])
	copy(b[64:128], sk.tr[:])

	offset := 128
	for i := 0; i < L44; i++ {
		packed := PackEta2(sk.s1[i])
		copy(b[offset:], packed)
		offset += EncodingSize3
	}
	for i := 0; i < K44; i++ {
		packed := PackEta2(sk.s2[i])
		copy(b[offset:], packed)
		offset += EncodingSize3
	}
	for i := 0; i < K44; i++ {
		packed := PackT0(sk.t0[i])
		copy(b[offset:], packed)
		offset += EncodingSize13
	}
	return b
}

// Bytes returns the encoded public key.
func (pk *PublicKey44) Bytes() []byte {
	b := make([]byte, PublicKeySize44)
	copy(b[:32], pk.rho[:])
	offset := 32
	for i := 0; i < K44; i++ {
		packed := PackT1(pk.t1[i])
		copy(b[offset:], packed)
		offset += EncodingSize10
	}
	return b
}

// Equal reports whether pk and other are the same public key.
func (pk *PublicKey44) Equal(other crypto.PublicKey) bool {
	o, ok := other.(*PublicKey44)
	if !ok {
		return false
	}
	return pk.rho == o.rho && pk.t1 == o.t1
}

// NewPublicKey44 parses an encoded public key.
func NewPublicKey44(b []byte) (*PublicKey44, error) {
	if len(b) != PublicKeySize44 {
		return nil, errors.New("mldsa: invalid public key length")
	}

	pk := &PublicKey44{}
	copy(pk.rho[:], b[:32])

	offset := 32
	for i := 0; i < K44; i++ {
		pk.t1[i] = UnpackT1(b[offset : offset+EncodingSize10])
		offset += EncodingSize10
	}

	for i := 0; i < K44; i++ {
		for j := 0; j < L44; j++ {
			pk.a[i*L44+j] = SampleNTTPoly(pk.rho[:], byte(j), byte(i))
		}
	}

	h := sha3.NewSHAKE256()
	h.Write(b)
	h.Read(pk.tr[:])

	return pk, nil
}

// NewPrivateKey44 parses an encoded private key.
func NewPrivateKey44(b []byte) (*PrivateKey44, error) {
	if len(b) != PrivateKeySize44 {
		return nil, errors.New("mldsa: invalid private key length")
	}

	sk := &PrivateKey44{}
	copy(sk.rho[:], b[:32])
	copy(sk.key[:], b[32:64])
	copy(sk.tr[:], b[64:128])

	offset := 128
	var err error
	for i := 0; i < L44; i++ {
		sk.s1[i], err = UnpackEta2(b[offset : offset+EncodingSize3])
		if err != nil {
			return nil, err
		}
		offset += EncodingSize3
	}
	for i := 0; i < K44; i++ {
		sk.s2[i], err = UnpackEta2(b[offset : offset+EncodingSize3])
		if err != nil {
			return nil, err
		}
		offset += EncodingSize3
	}
	for i := 0; i < K44; i++ {
		sk.t0[i] = UnpackT0(b[offset : offset+EncodingSize13])
		offset += EncodingSize13
	}

	for i := 0; i < K44; i++ {
		for j := 0; j < L44; j++ {
			sk.a[i*L44+j] = SampleNTTPoly(sk.rho[:], byte(j), byte(i))
		}
	}

	return sk, nil
}

// Public returns the public key corresponding to this private key.
// This implements the crypto.Signer interface.
func (sk *PrivateKey44) Public() crypto.PublicKey {
	// Reconstruct public key from private key components
	pk := &PublicKey44{
		rho: sk.rho,
		tr:  sk.tr,
		a:   sk.a,
	}
	// Compute t1 from s1, s2 via A*s1 + s2, then take high bits
	var s1NTT [L44]NttElement
	for i := 0; i < L44; i++ {
		s1NTT[i] = NTT(sk.s1[i])
	}
	for i := 0; i < K44; i++ {
		var acc NttElement
		for j := 0; j < L44; j++ {
			acc = PolyAdd(acc, NttMul(sk.a[i*L44+j], s1NTT[j]))
		}
		t := PolyAdd(InvNTT(acc), sk.s2[i])
		for j := 0; j < N; j++ {
			pk.t1[i][j], _ = Power2Round(t[j])
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
func (sk *PrivateKey44) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return sk.SignMessage(rand, digest, opts)
}

// SignMessage signs msg with the private key.
// This implements the crypto.MessageSigner interface.
//
// If opts is *SignerOpts, its Context field is used for domain separation.
// If opts is nil or not *SignerOpts, no context is used.
// Returns an error if opts specifies a hash function, as ML-DSA signs messages directly.
func (sk *PrivateKey44) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
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
func (sk *PrivateKey44) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error) {
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
func (sk *PrivateKey44) signInternal(rnd, mPrime []byte) ([]byte, error) {
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

	var s1NTT [L44]NttElement
	var s2NTT [K44]NttElement
	var t0NTT [K44]NttElement
	for i := 0; i < L44; i++ {
		s1NTT[i] = NTT(sk.s1[i])
	}
	for i := 0; i < K44; i++ {
		s2NTT[i] = NTT(sk.s2[i])
		t0NTT[i] = NTT(sk.t0[i])
	}

	var seedBuf [66]byte
	copy(seedBuf[:64], rhoPrime[:])

	for kappa := uint16(0); ; kappa += L44 {
		var y [L44]RingElement
		for i := 0; i < L44; i++ {
			seedBuf[64] = byte(kappa + uint16(i))
			seedBuf[65] = byte((kappa + uint16(i)) >> 8)
			y[i] = ExpandMask(seedBuf[:], Gamma1Bits17)
		}

		var yNTT [L44]NttElement
		for i := 0; i < L44; i++ {
			yNTT[i] = NTT(y[i])
		}

		var w [K44]RingElement
		var w1 [K44]RingElement
		for i := 0; i < K44; i++ {
			var acc NttElement
			for j := 0; j < L44; j++ {
				acc = PolyAdd(acc, NttMul(sk.a[i*L44+j], yNTT[j]))
			}
			w[i] = InvNTT(acc)

			for j := 0; j < N; j++ {
				w1[i][j] = FieldElement(HighBits(w[i][j], Gamma2QMinus1Div88))
			}
		}

		h.Reset()
		h.Write(mu[:])
		for i := 0; i < K44; i++ {
			h.Write(PackW1_6(w1[i]))
		}
		var cTilde [Lambda128 / 4]byte
		h.Read(cTilde[:])

		c := SampleChallenge(cTilde[:], Tau39)
		cNTT := NTT(c)

		var z [L44]RingElement
		for i := 0; i < L44; i++ {
			cs1 := InvNTT(NttMul(cNTT, s1NTT[i]))
			z[i] = PolyAdd(y[i], cs1)
		}

		if VectorInfinityNorm(z[:]) >= Gamma1Pow17-Beta44 {
			continue
		}

		var r0 [K44][N]int32
		for i := 0; i < K44; i++ {
			cs2 := InvNTT(NttMul(cNTT, s2NTT[i]))
			for j := 0; j < N; j++ {
				_, r0[i][j] = Decompose(fieldSub(w[i][j], cs2[j]), Gamma2QMinus1Div88)
			}
		}

		if vectorInfinityNormSigned(r0[:]) >= int32(Gamma2QMinus1Div88-Beta44) {
			continue
		}

		var ct0 [K44]RingElement
		for i := 0; i < K44; i++ {
			ct0[i] = InvNTT(NttMul(cNTT, t0NTT[i]))
		}

		if VectorInfinityNorm(ct0[:]) >= Gamma2QMinus1Div88 {
			continue
		}

		var hints [K44]RingElement
		for i := 0; i < K44; i++ {
			cs2 := InvNTT(NttMul(cNTT, s2NTT[i]))
			for j := 0; j < N; j++ {
				r := fieldSub(w[i][j], cs2[j])
				hints[i][j] = MakeHint(ct0[i][j], r, Gamma2QMinus1Div88)
			}
		}

		if CountOnes(hints[:]) > Omega80 {
			continue
		}

		sig := make([]byte, SignatureSize44)
		copy(sig[:len(cTilde)], cTilde[:])
		offset := len(cTilde)
		for i := 0; i < L44; i++ {
			packed := PackZ17(z[i])
			copy(sig[offset:], packed)
			offset += EncodingSize18
		}
		hintPacked := PackHint(hints[:], Omega80)
		copy(sig[offset:], hintPacked)

		return sig, nil
	}
}

// Verify checks the signature.
func (pk *PublicKey44) Verify(sig, message, context []byte) bool {
	if len(sig) != SignatureSize44 {
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
func (pk *PublicKey44) verifyInternal(sig, mPrime []byte) bool {
	// Compute mu = H(tr || M')
	h := sha3.NewSHAKE256()
	h.Write(pk.tr[:])
	h.Write(mPrime)

	var mu [64]byte
	h.Read(mu[:])

	cTilde := sig[:Lambda128/4]
	offset := Lambda128 / 4

	var z [L44]RingElement
	for i := 0; i < L44; i++ {
		z[i] = UnpackZ17(sig[offset : offset+EncodingSize18])
		offset += EncodingSize18
	}

	if VectorInfinityNorm(z[:]) >= Gamma1Pow17-Beta44 {
		return false
	}

	var hints [K44]RingElement
	if !UnpackHint(sig[offset:], hints[:], Omega80) {
		return false
	}

	c := SampleChallenge(cTilde, Tau39)
	cNTT := NTT(c)

	var zNTT [L44]NttElement
	for i := 0; i < L44; i++ {
		zNTT[i] = NTT(z[i])
	}

	var t1NTT [K44]NttElement
	for i := 0; i < K44; i++ {
		var t1Scaled RingElement
		for j := 0; j < N; j++ {
			t1Scaled[j] = pk.t1[i][j] << D
		}
		t1NTT[i] = NTT(t1Scaled)
	}

	var w1 [K44]RingElement
	h.Reset()
	h.Write(mu[:])

	for i := 0; i < K44; i++ {
		var acc NttElement
		for j := 0; j < L44; j++ {
			acc = PolyAdd(acc, NttMul(pk.a[i*L44+j], zNTT[j]))
		}
		ct1 := NttMul(cNTT, t1NTT[i])
		acc = PolySub(acc, ct1)
		wApprox := InvNTT(acc)

		for j := 0; j < N; j++ {
			w1[i][j] = UseHint(hints[i][j], wApprox[j], Gamma2QMinus1Div88)
		}

		h.Write(PackW1_6(w1[i]))
	}

	var cTildeCheck [Lambda128 / 4]byte
	h.Read(cTildeCheck[:])

	var diff byte
	for i := range cTilde {
		diff |= cTilde[i] ^ cTildeCheck[i]
	}
	return diff == 0
}

// Sign signs digest with the key pair's private key.
// This implements the crypto.Signer interface.
func (key *Key44) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.PrivateKey44.Sign(rand, digest, opts)
}

// SignMessage signs msg with the key pair's private key.
// This implements the crypto.MessageSigner interface.
func (key *Key44) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.PrivateKey44.SignMessage(rand, msg, opts)
}

// SignWithContext signs a message with an optional context string using the key pair.
func (key *Key44) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error) {
	return key.PrivateKey44.SignWithContext(rand, message, context)
}
