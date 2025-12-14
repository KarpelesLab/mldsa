package mldsa

import (
	"crypto"
	"crypto/sha3"
	"errors"
	"io"
)

// PrivateKey87 is the private key for ML-DSA-87.
type PrivateKey87 struct {
	rho [32]byte             // Public seed
	key [32]byte             // Private seed for signing
	tr  [64]byte             // H(pk)
	s1  [l87]ringElement     // Secret vector
	s2  [k87]ringElement     // Secret vector
	t0  [k87]ringElement     // Low bits of t
	a   [k87 * l87]nttElement // Matrix A in NTT form
}

// PublicKey87 is the public key for ML-DSA-87.
type PublicKey87 struct {
	rho [32]byte             // Public seed
	t1  [k87]ringElement     // High bits of t
	tr  [64]byte             // H(pk)
	a   [k87 * l87]nttElement // Matrix A in NTT form
}

// Key87 is a key pair for ML-DSA-87.
type Key87 struct {
	PrivateKey87
	seed [32]byte         // Original seed
	t1   [k87]ringElement // Public key component
}

// GenerateKey87 generates a new ML-DSA-87 key pair.
func GenerateKey87(rand io.Reader) (*Key87, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	return NewKey87(seed[:])
}

// NewKey87 creates a key pair from a seed.
func NewKey87(seed []byte) (*Key87, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mldsa: invalid seed length")
	}

	key := &Key87{}
	copy(key.seed[:], seed)
	key.generate()
	return key, nil
}

func (key *Key87) generate() {
	h := sha3.NewSHAKE256()
	h.Write(key.seed[:])
	h.Write([]byte{k87, l87})

	var expanded [128]byte
	h.Read(expanded[:])

	copy(key.rho[:], expanded[:32])
	rho1 := expanded[32:96]
	copy(key.key[:], expanded[96:128])

	for i := 0; i < l87; i++ {
		key.s1[i] = sampleBoundedPoly(rho1, eta2, uint16(i))
	}
	for i := 0; i < k87; i++ {
		key.s2[i] = sampleBoundedPoly(rho1, eta2, uint16(l87+i))
	}

	for i := 0; i < k87; i++ {
		for j := 0; j < l87; j++ {
			key.a[i*l87+j] = sampleNTTPoly(key.rho[:], byte(j), byte(i))
		}
	}

	var s1NTT [l87]nttElement
	for i := 0; i < l87; i++ {
		s1NTT[i] = ntt(key.s1[i])
	}

	var t [k87]ringElement
	for i := 0; i < k87; i++ {
		var acc nttElement
		for j := 0; j < l87; j++ {
			acc = polyAdd(acc, nttMul(key.a[i*l87+j], s1NTT[j]))
		}
		t[i] = polyAdd(invNTT(acc), key.s2[i])

		for j := 0; j < n; j++ {
			key.t1[i][j], key.t0[i][j] = power2Round(t[i][j])
		}
	}

	pkBytes := key.publicKeyBytes()
	h.Reset()
	h.Write(pkBytes)
	h.Read(key.tr[:])
}

func (key *Key87) publicKeyBytes() []byte {
	b := make([]byte, PublicKeySize87)
	copy(b[:32], key.rho[:])
	offset := 32
	for i := 0; i < k87; i++ {
		packed := packT1(key.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
	}
	return b
}

// PublicKey returns the public key.
func (key *Key87) PublicKey() *PublicKey87 {
	return &PublicKey87{
		rho: key.rho,
		t1:  key.t1,
		tr:  key.tr,
		a:   key.a,
	}
}

// Bytes returns the seed.
func (key *Key87) Bytes() []byte {
	b := make([]byte, SeedSize)
	copy(b, key.seed[:])
	return b
}

// PrivateKeyBytes returns the full encoded private key.
func (key *Key87) PrivateKeyBytes() []byte {
	return key.PrivateKey87.Bytes()
}

// Bytes returns the encoded private key.
func (sk *PrivateKey87) Bytes() []byte {
	b := make([]byte, PrivateKeySize87)
	copy(b[:32], sk.rho[:])
	copy(b[32:64], sk.key[:])
	copy(b[64:128], sk.tr[:])

	offset := 128
	for i := 0; i < l87; i++ {
		packed := packEta2(sk.s1[i])
		copy(b[offset:], packed)
		offset += encodingSize3
	}
	for i := 0; i < k87; i++ {
		packed := packEta2(sk.s2[i])
		copy(b[offset:], packed)
		offset += encodingSize3
	}
	for i := 0; i < k87; i++ {
		packed := packT0(sk.t0[i])
		copy(b[offset:], packed)
		offset += encodingSize13
	}
	return b
}

// Bytes returns the encoded public key.
func (pk *PublicKey87) Bytes() []byte {
	b := make([]byte, PublicKeySize87)
	copy(b[:32], pk.rho[:])
	offset := 32
	for i := 0; i < k87; i++ {
		packed := packT1(pk.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
	}
	return b
}

// Equal reports whether pk and other are the same public key.
func (pk *PublicKey87) Equal(other crypto.PublicKey) bool {
	o, ok := other.(*PublicKey87)
	if !ok {
		return false
	}
	return pk.rho == o.rho && pk.t1 == o.t1
}

// NewPublicKey87 parses an encoded public key.
func NewPublicKey87(b []byte) (*PublicKey87, error) {
	if len(b) != PublicKeySize87 {
		return nil, errors.New("mldsa: invalid public key length")
	}

	pk := &PublicKey87{}
	copy(pk.rho[:], b[:32])

	offset := 32
	for i := 0; i < k87; i++ {
		pk.t1[i] = unpackT1(b[offset : offset+encodingSize10])
		offset += encodingSize10
	}

	for i := 0; i < k87; i++ {
		for j := 0; j < l87; j++ {
			pk.a[i*l87+j] = sampleNTTPoly(pk.rho[:], byte(j), byte(i))
		}
	}

	h := sha3.NewSHAKE256()
	h.Write(b)
	h.Read(pk.tr[:])

	return pk, nil
}

// NewPrivateKey87 parses an encoded private key.
func NewPrivateKey87(b []byte) (*PrivateKey87, error) {
	if len(b) != PrivateKeySize87 {
		return nil, errors.New("mldsa: invalid private key length")
	}

	sk := &PrivateKey87{}
	copy(sk.rho[:], b[:32])
	copy(sk.key[:], b[32:64])
	copy(sk.tr[:], b[64:128])

	offset := 128
	var err error
	for i := 0; i < l87; i++ {
		sk.s1[i], err = unpackEta2(b[offset : offset+encodingSize3])
		if err != nil {
			return nil, err
		}
		offset += encodingSize3
	}
	for i := 0; i < k87; i++ {
		sk.s2[i], err = unpackEta2(b[offset : offset+encodingSize3])
		if err != nil {
			return nil, err
		}
		offset += encodingSize3
	}
	for i := 0; i < k87; i++ {
		sk.t0[i] = unpackT0(b[offset : offset+encodingSize13])
		offset += encodingSize13
	}

	for i := 0; i < k87; i++ {
		for j := 0; j < l87; j++ {
			sk.a[i*l87+j] = sampleNTTPoly(sk.rho[:], byte(j), byte(i))
		}
	}

	return sk, nil
}

// Sign creates a signature.
func (sk *PrivateKey87) Sign(rand io.Reader, message, context []byte) ([]byte, error) {
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
func (sk *PrivateKey87) signInternal(rnd, mPrime []byte) ([]byte, error) {
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

	var s1NTT [l87]nttElement
	var s2NTT [k87]nttElement
	var t0NTT [k87]nttElement
	for i := 0; i < l87; i++ {
		s1NTT[i] = ntt(sk.s1[i])
	}
	for i := 0; i < k87; i++ {
		s2NTT[i] = ntt(sk.s2[i])
		t0NTT[i] = ntt(sk.t0[i])
	}

	var seedBuf [66]byte
	copy(seedBuf[:64], rhoPrime[:])

	for kappa := uint16(0); ; kappa += l87 {
		var y [l87]ringElement
		for i := 0; i < l87; i++ {
			seedBuf[64] = byte(kappa + uint16(i))
			seedBuf[65] = byte((kappa + uint16(i)) >> 8)
			y[i] = expandMask(seedBuf[:], gamma1Bits19)
		}

		var yNTT [l87]nttElement
		for i := 0; i < l87; i++ {
			yNTT[i] = ntt(y[i])
		}

		var w [k87]ringElement
		var w1 [k87]ringElement
		for i := 0; i < k87; i++ {
			var acc nttElement
			for j := 0; j < l87; j++ {
				acc = polyAdd(acc, nttMul(sk.a[i*l87+j], yNTT[j]))
			}
			w[i] = invNTT(acc)

			for j := 0; j < n; j++ {
				w1[i][j] = fieldElement(highBits(w[i][j], gamma2QMinus1Div32))
			}
		}

		h.Reset()
		h.Write(mu[:])
		for i := 0; i < k87; i++ {
			h.Write(packW1_4(w1[i]))
		}
		var cTilde [lambda256 / 4]byte
		h.Read(cTilde[:])

		c := sampleChallenge(cTilde[:], tau60)
		cNTT := ntt(c)

		var z [l87]ringElement
		for i := 0; i < l87; i++ {
			cs1 := invNTT(nttMul(cNTT, s1NTT[i]))
			z[i] = polyAdd(y[i], cs1)
		}

		if vectorInfinityNorm(z[:]) >= gamma1Pow19-beta87 {
			continue
		}

		var r0 [k87][n]int32
		for i := 0; i < k87; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				_, r0[i][j] = decompose(fieldSub(w[i][j], cs2[j]), gamma2QMinus1Div32)
			}
		}

		if vectorInfinityNormSigned(r0[:]) >= int32(gamma2QMinus1Div32-beta87) {
			continue
		}

		var ct0 [k87]ringElement
		for i := 0; i < k87; i++ {
			ct0[i] = invNTT(nttMul(cNTT, t0NTT[i]))
		}

		if vectorInfinityNorm(ct0[:]) >= gamma2QMinus1Div32 {
			continue
		}

		var hints [k87]ringElement
		for i := 0; i < k87; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				r := fieldSub(w[i][j], cs2[j])
				hints[i][j] = makeHint(ct0[i][j], r, gamma2QMinus1Div32)
			}
		}

		if countOnes(hints[:]) > omega75 {
			continue
		}

		sig := make([]byte, SignatureSize87)
		copy(sig[:len(cTilde)], cTilde[:])
		offset := len(cTilde)
		for i := 0; i < l87; i++ {
			packed := packZ19(z[i])
			copy(sig[offset:], packed)
			offset += encodingSize20
		}
		hintPacked := packHint(hints[:], omega75)
		copy(sig[offset:], hintPacked)

		return sig, nil
	}
}

// Verify checks the signature.
func (pk *PublicKey87) Verify(sig, message, context []byte) bool {
	if len(sig) != SignatureSize87 {
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
func (pk *PublicKey87) verifyInternal(sig, mPrime []byte) bool {
	// Compute mu = H(tr || M')
	h := sha3.NewSHAKE256()
	h.Write(pk.tr[:])
	h.Write(mPrime)

	var mu [64]byte
	h.Read(mu[:])

	cTilde := sig[:lambda256/4]
	offset := lambda256 / 4

	var z [l87]ringElement
	for i := 0; i < l87; i++ {
		z[i] = unpackZ19Sig(sig[offset : offset+encodingSize20])
		offset += encodingSize20
	}

	if vectorInfinityNorm(z[:]) >= gamma1Pow19-beta87 {
		return false
	}

	var hints [k87]ringElement
	if !unpackHint(sig[offset:], hints[:], omega75) {
		return false
	}

	c := sampleChallenge(cTilde, tau60)
	cNTT := ntt(c)

	var zNTT [l87]nttElement
	for i := 0; i < l87; i++ {
		zNTT[i] = ntt(z[i])
	}

	var t1NTT [k87]nttElement
	for i := 0; i < k87; i++ {
		var t1Scaled ringElement
		for j := 0; j < n; j++ {
			t1Scaled[j] = pk.t1[i][j] << d
		}
		t1NTT[i] = ntt(t1Scaled)
	}

	var w1 [k87]ringElement
	h.Reset()
	h.Write(mu[:])

	for i := 0; i < k87; i++ {
		var acc nttElement
		for j := 0; j < l87; j++ {
			acc = polyAdd(acc, nttMul(pk.a[i*l87+j], zNTT[j]))
		}
		ct1 := nttMul(cNTT, t1NTT[i])
		acc = polySub(acc, ct1)
		wApprox := invNTT(acc)

		for j := 0; j < n; j++ {
			w1[i][j] = useHint(hints[i][j], wApprox[j], gamma2QMinus1Div32)
		}

		h.Write(packW1_4(w1[i]))
	}

	var cTildeCheck [lambda256 / 4]byte
	h.Read(cTildeCheck[:])

	var diff byte
	for i := range cTilde {
		diff |= cTilde[i] ^ cTildeCheck[i]
	}
	return diff == 0
}

// Sign creates a signature using the key pair.
func (key *Key87) Sign(rand io.Reader, message, context []byte) ([]byte, error) {
	return key.PrivateKey87.Sign(rand, message, context)
}
