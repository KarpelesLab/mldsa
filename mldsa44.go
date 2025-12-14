package mldsa

import (
	"crypto"
	"crypto/sha3"
	"errors"
	"io"
)

// PrivateKey44 is the private key for ML-DSA-44.
type PrivateKey44 struct {
	rho [32]byte             // Public seed
	key [32]byte             // Private seed for signing
	tr  [64]byte             // H(pk)
	s1  [l44]ringElement     // Secret vector
	s2  [k44]ringElement     // Secret vector
	t0  [k44]ringElement     // Low bits of t
	a   [k44 * l44]nttElement // Matrix A in NTT form
}

// PublicKey44 is the public key for ML-DSA-44.
type PublicKey44 struct {
	rho [32]byte             // Public seed
	t1  [k44]ringElement     // High bits of t
	tr  [64]byte             // H(pk)
	a   [k44 * l44]nttElement // Matrix A in NTT form
}

// Key44 is a key pair for ML-DSA-44.
type Key44 struct {
	PrivateKey44
	seed [32]byte         // Original seed
	t1   [k44]ringElement // Public key component
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
	h.Write([]byte{k44, l44})

	var expanded [128]byte
	h.Read(expanded[:])

	copy(key.rho[:], expanded[:32])
	rho1 := expanded[32:96]
	copy(key.key[:], expanded[96:128])

	for i := 0; i < l44; i++ {
		key.s1[i] = sampleBoundedPoly(rho1, eta2, uint16(i))
	}
	for i := 0; i < k44; i++ {
		key.s2[i] = sampleBoundedPoly(rho1, eta2, uint16(l44+i))
	}

	for i := 0; i < k44; i++ {
		for j := 0; j < l44; j++ {
			key.a[i*l44+j] = sampleNTTPoly(key.rho[:], byte(j), byte(i))
		}
	}

	var s1NTT [l44]nttElement
	for i := 0; i < l44; i++ {
		s1NTT[i] = ntt(key.s1[i])
	}

	var t [k44]ringElement
	for i := 0; i < k44; i++ {
		var acc nttElement
		for j := 0; j < l44; j++ {
			acc = polyAdd(acc, nttMul(key.a[i*l44+j], s1NTT[j]))
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

func (key *Key44) publicKeyBytes() []byte {
	b := make([]byte, PublicKeySize44)
	copy(b[:32], key.rho[:])
	offset := 32
	for i := 0; i < k44; i++ {
		packed := packT1(key.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
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
	for i := 0; i < l44; i++ {
		packed := packEta2(sk.s1[i])
		copy(b[offset:], packed)
		offset += encodingSize3
	}
	for i := 0; i < k44; i++ {
		packed := packEta2(sk.s2[i])
		copy(b[offset:], packed)
		offset += encodingSize3
	}
	for i := 0; i < k44; i++ {
		packed := packT0(sk.t0[i])
		copy(b[offset:], packed)
		offset += encodingSize13
	}
	return b
}

// Bytes returns the encoded public key.
func (pk *PublicKey44) Bytes() []byte {
	b := make([]byte, PublicKeySize44)
	copy(b[:32], pk.rho[:])
	offset := 32
	for i := 0; i < k44; i++ {
		packed := packT1(pk.t1[i])
		copy(b[offset:], packed)
		offset += encodingSize10
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
	for i := 0; i < k44; i++ {
		pk.t1[i] = unpackT1(b[offset : offset+encodingSize10])
		offset += encodingSize10
	}

	for i := 0; i < k44; i++ {
		for j := 0; j < l44; j++ {
			pk.a[i*l44+j] = sampleNTTPoly(pk.rho[:], byte(j), byte(i))
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
	for i := 0; i < l44; i++ {
		sk.s1[i], err = unpackEta2(b[offset : offset+encodingSize3])
		if err != nil {
			return nil, err
		}
		offset += encodingSize3
	}
	for i := 0; i < k44; i++ {
		sk.s2[i], err = unpackEta2(b[offset : offset+encodingSize3])
		if err != nil {
			return nil, err
		}
		offset += encodingSize3
	}
	for i := 0; i < k44; i++ {
		sk.t0[i] = unpackT0(b[offset : offset+encodingSize13])
		offset += encodingSize13
	}

	for i := 0; i < k44; i++ {
		for j := 0; j < l44; j++ {
			sk.a[i*l44+j] = sampleNTTPoly(sk.rho[:], byte(j), byte(i))
		}
	}

	return sk, nil
}

// Sign creates a signature.
func (sk *PrivateKey44) Sign(rand io.Reader, message, context []byte) ([]byte, error) {
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

	var s1NTT [l44]nttElement
	var s2NTT [k44]nttElement
	var t0NTT [k44]nttElement
	for i := 0; i < l44; i++ {
		s1NTT[i] = ntt(sk.s1[i])
	}
	for i := 0; i < k44; i++ {
		s2NTT[i] = ntt(sk.s2[i])
		t0NTT[i] = ntt(sk.t0[i])
	}

	var seedBuf [66]byte
	copy(seedBuf[:64], rhoPrime[:])

	for kappa := uint16(0); ; kappa += l44 {
		var y [l44]ringElement
		for i := 0; i < l44; i++ {
			seedBuf[64] = byte(kappa + uint16(i))
			seedBuf[65] = byte((kappa + uint16(i)) >> 8)
			y[i] = expandMask(seedBuf[:], gamma1Bits17)
		}

		var yNTT [l44]nttElement
		for i := 0; i < l44; i++ {
			yNTT[i] = ntt(y[i])
		}

		var w [k44]ringElement
		var w1 [k44]ringElement
		for i := 0; i < k44; i++ {
			var acc nttElement
			for j := 0; j < l44; j++ {
				acc = polyAdd(acc, nttMul(sk.a[i*l44+j], yNTT[j]))
			}
			w[i] = invNTT(acc)

			for j := 0; j < n; j++ {
				w1[i][j] = fieldElement(highBits(w[i][j], gamma2QMinus1Div88))
			}
		}

		h.Reset()
		h.Write(mu[:])
		for i := 0; i < k44; i++ {
			h.Write(packW1_6(w1[i]))
		}
		var cTilde [lambda128 / 4]byte
		h.Read(cTilde[:])

		c := sampleChallenge(cTilde[:], tau39)
		cNTT := ntt(c)

		var z [l44]ringElement
		for i := 0; i < l44; i++ {
			cs1 := invNTT(nttMul(cNTT, s1NTT[i]))
			z[i] = polyAdd(y[i], cs1)
		}

		if vectorInfinityNorm(z[:]) >= gamma1Pow17-beta44 {
			continue
		}

		var r0 [k44][n]int32
		for i := 0; i < k44; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				_, r0[i][j] = decompose(fieldSub(w[i][j], cs2[j]), gamma2QMinus1Div88)
			}
		}

		if vectorInfinityNormSigned(r0[:]) >= int32(gamma2QMinus1Div88-beta44) {
			continue
		}

		var ct0 [k44]ringElement
		for i := 0; i < k44; i++ {
			ct0[i] = invNTT(nttMul(cNTT, t0NTT[i]))
		}

		if vectorInfinityNorm(ct0[:]) >= gamma2QMinus1Div88 {
			continue
		}

		var hints [k44]ringElement
		for i := 0; i < k44; i++ {
			cs2 := invNTT(nttMul(cNTT, s2NTT[i]))
			for j := 0; j < n; j++ {
				r := fieldSub(w[i][j], cs2[j])
				hints[i][j] = makeHint(ct0[i][j], r, gamma2QMinus1Div88)
			}
		}

		if countOnes(hints[:]) > omega80 {
			continue
		}

		sig := make([]byte, SignatureSize44)
		copy(sig[:len(cTilde)], cTilde[:])
		offset := len(cTilde)
		for i := 0; i < l44; i++ {
			packed := packZ17(z[i])
			copy(sig[offset:], packed)
			offset += encodingSize18
		}
		hintPacked := packHint(hints[:], omega80)
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

	cTilde := sig[:lambda128/4]
	offset := lambda128 / 4

	var z [l44]ringElement
	for i := 0; i < l44; i++ {
		z[i] = unpackZ17Sig(sig[offset : offset+encodingSize18])
		offset += encodingSize18
	}

	if vectorInfinityNorm(z[:]) >= gamma1Pow17-beta44 {
		return false
	}

	var hints [k44]ringElement
	if !unpackHint(sig[offset:], hints[:], omega80) {
		return false
	}

	c := sampleChallenge(cTilde, tau39)
	cNTT := ntt(c)

	var zNTT [l44]nttElement
	for i := 0; i < l44; i++ {
		zNTT[i] = ntt(z[i])
	}

	var t1NTT [k44]nttElement
	for i := 0; i < k44; i++ {
		var t1Scaled ringElement
		for j := 0; j < n; j++ {
			t1Scaled[j] = pk.t1[i][j] << d
		}
		t1NTT[i] = ntt(t1Scaled)
	}

	var w1 [k44]ringElement
	h.Reset()
	h.Write(mu[:])

	for i := 0; i < k44; i++ {
		var acc nttElement
		for j := 0; j < l44; j++ {
			acc = polyAdd(acc, nttMul(pk.a[i*l44+j], zNTT[j]))
		}
		ct1 := nttMul(cNTT, t1NTT[i])
		acc = polySub(acc, ct1)
		wApprox := invNTT(acc)

		for j := 0; j < n; j++ {
			w1[i][j] = useHint(hints[i][j], wApprox[j], gamma2QMinus1Div88)
		}

		h.Write(packW1_6(w1[i]))
	}

	var cTildeCheck [lambda128 / 4]byte
	h.Read(cTildeCheck[:])

	var diff byte
	for i := range cTilde {
		diff |= cTilde[i] ^ cTildeCheck[i]
	}
	return diff == 0
}

// Sign creates a signature using the key pair.
func (key *Key44) Sign(rand io.Reader, message, context []byte) ([]byte, error) {
	return key.PrivateKey44.Sign(rand, message, context)
}
