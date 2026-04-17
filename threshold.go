package mldsa

// Threshold-ML-DSA primitives.
//
// This file exposes the internal building blocks used by threshold ML-DSA
// implementations (e.g. github.com/KarpelesLab/tss-lib/v2/mldsatss, based
// on "Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with
// Identifiable Aborts", Borin, Celi, del Pino, Espitau, Niot, Prest
// [ePrint 2025/1166]).
//
// WARNING: The threshold surface here is research-grade and is NOT stable.
// It is intended for experimentation and prototype integration, not for
// production use.

import (
	"crypto/sha3"
	"encoding/binary"
	"math"
)

// Exported type aliases for the ring and NTT domain.
type (
	FieldElement = fieldElement
	RingElement  = ringElement
	NttElement   = nttElement
)

// Exported FIPS 204 scalar constants.
const (
	N = n
	Q = q
	D = d
)

// ML-DSA-44 parameters (used by the threshold variant).
const (
	K44       = k44
	L44       = l44
	Eta44     = eta2
	Tau44     = tau39
	Gamma1_44 = gamma1Pow17
	Gamma2_44 = gamma2QMinus1Div88
	Omega44   = omega80
	Lambda44  = lambda128
	Beta44    = beta44
)

// Exported encoding sizes.
const (
	EncodingSizeEta2  = encodingSize3
	EncodingSizeZ17   = encodingSize18
	EncodingSizeT0    = encodingSize13
	EncodingSizeT1    = encodingSize10
	EncodingSizeW1_44 = encodingSize6

	// PackPolyQSize is the size of a packed full-range (23-bit) polynomial.
	PackPolyQSize = n * 23 / 8 // 736 bytes
)

// --- Ring arithmetic -------------------------------------------------------

func RingAdd(a, b RingElement) RingElement { return polyAdd(a, b) }
func RingSub(a, b RingElement) RingElement { return polySub(a, b) }
func NttAdd(a, b NttElement) NttElement    { return polyAdd(a, b) }
func NttSub(a, b NttElement) NttElement    { return polySub(a, b) }
func NTT(f RingElement) NttElement         { return ntt(f) }
func InvNTT(f NttElement) RingElement      { return invNTT(f) }
func NttMul(a, b NttElement) NttElement    { return nttMul(a, b) }

// --- Decomposition & hints (ML-DSA-44) -------------------------------------

func Power2Round(r FieldElement) (FieldElement, FieldElement) { return power2Round(r) }
func Decompose44(r FieldElement) (uint32, int32)              { return decompose(r, gamma2QMinus1Div88) }
func HighBits44(r FieldElement) uint32                        { return highBits(r, gamma2QMinus1Div88) }
func MakeHint44(z, r FieldElement) FieldElement               { return makeHint(z, r, gamma2QMinus1Div88) }
func UseHint44(h, r FieldElement) FieldElement                { return useHint(h, r, gamma2QMinus1Div88) }

// --- Norms -----------------------------------------------------------------

func InfinityNorm(a FieldElement) uint32        { return infinityNorm(a) }
func PolyInfinityNorm(f RingElement) uint32     { return polyInfinityNorm(f) }
func VectorInfinityNorm(v []RingElement) uint32 { return vectorInfinityNorm(v) }
func CountOnes(v []RingElement) int             { return countOnes(v) }

// --- Samplers --------------------------------------------------------------

// SampleA returns A[i][j] in NTT form, derived from rho as in FIPS 204 ExpandA.
func SampleA(rho []byte, i, j int) NttElement {
	return sampleNTTPoly(rho, byte(j), byte(i))
}

// SampleBoundedEta2 derives a polynomial with coefficients in [-2, 2]
// from (seed, nonce) using rejection on SHAKE256 output.
func SampleBoundedEta2(seed []byte, nonce uint16) RingElement {
	return sampleBoundedPoly(seed, eta2, nonce)
}

// SampleBoundedEta4 is the η=4 variant (ML-DSA-65).
func SampleBoundedEta4(seed []byte, nonce uint16) RingElement {
	return sampleBoundedPoly(seed, eta4, nonce)
}

// SampleInBall44 derives the challenge polynomial c with τ=39 non-zero
// coefficients in {-1, 1} (FIPS 204 Algorithm 29, ML-DSA-44).
func SampleInBall44(seed []byte) RingElement {
	return sampleChallenge(seed, tau39)
}

// ExpandMask17 derives a single polynomial with coefficients in [-γ₁+1, γ₁]
// where γ₁ = 2^17 (ML-DSA-44 nonce layout).
func ExpandMask17(seed []byte) RingElement { return expandMask(seed, gamma1Bits17) }

// --- Packing ---------------------------------------------------------------

func PackT1(f RingElement) []byte                 { return packT1(f) }
func UnpackT1(b []byte) RingElement               { return unpackT1(b) }
func PackT0(f RingElement) []byte                 { return packT0(f) }
func UnpackT0(b []byte) RingElement               { return unpackT0(b) }
func PackEta2(f RingElement) []byte               { return packEta2(f) }
func UnpackEta2(b []byte) (RingElement, error)    { return unpackEta2(b) }
func PackZ17(f RingElement) []byte                { return packZ17(f) }
func UnpackZ17(b []byte) RingElement              { return unpackZ17Sig(b) }
func PackW1_44(f RingElement) []byte              { return packW1_6(f) }
func PackHint44(v []RingElement) []byte           { return packHint(v, omega80) }
func UnpackHint44(b []byte, v []RingElement) bool { return unpackHint(b, v, omega80) }

// PackPolyQ packs a full-range polynomial with 23-bit coefficients into b.
// Used for threshold w commitments, where w values span all of Z_q.
// len(b) must be at least PackPolyQSize. Coefficients must already be in [0, q).
func PackPolyQ(f RingElement, b []byte) {
	var bitBuf uint64
	var bitLen uint
	bIdx := 0
	for i := 0; i < n; i++ {
		bitBuf |= uint64(f[i]) << bitLen
		bitLen += 23
		for bitLen >= 8 {
			b[bIdx] = byte(bitBuf)
			bitBuf >>= 8
			bitLen -= 8
			bIdx++
		}
	}
}

// UnpackPolyQ unpacks a polynomial packed with PackPolyQ.
func UnpackPolyQ(b []byte) RingElement {
	var f RingElement
	var bitBuf uint64
	var bitLen uint
	bIdx := 0
	for i := 0; i < n; i++ {
		for bitLen < 23 {
			bitBuf |= uint64(b[bIdx]) << bitLen
			bIdx++
			bitLen += 8
		}
		f[i] = fieldElement(bitBuf & ((1 << 23) - 1))
		bitBuf >>= 23
		bitLen -= 23
	}
	return f
}

// --- FVec (float vector for hyperball sampling) ----------------------------

// FVec44 is a float64 vector of L+K polynomials × N coefficients used by
// threshold ML-DSA-44 rejection sampling (see ePrint 2025/1166).
type FVec44 [n * (k44 + l44)]float64

// Add sets v to w + u coefficient-wise.
func (v *FVec44) Add(w, u *FVec44) {
	for i := range v {
		v[i] = w[i] + u[i]
	}
}

// From loads (s1, s2) into v, recentering each coefficient modulo q into
// (-q/2, q/2] before converting to float64. Requires len(s1) == L44 and
// len(s2) == K44.
func (v *FVec44) From(s1 []RingElement, s2 []RingElement) {
	if len(s1) != l44 || len(s2) != k44 {
		panic("mldsa: FVec44.From expects len(s1)==L44, len(s2)==K44")
	}
	for i := 0; i < l44+k44; i++ {
		var poly RingElement
		if i < l44 {
			poly = s1[i]
		} else {
			poly = s2[i-l44]
		}
		for j := 0; j < n; j++ {
			u := int32(poly[j])
			u += q / 2
			t := u - q
			u = t + (t>>31)&q
			u -= q / 2
			v[i*n+j] = float64(u)
		}
	}
}

// Round writes the rounded, mod-q-normalized integer value of v back into
// (s1, s2). Requires len(s1) == L44 and len(s2) == K44.
func (v *FVec44) Round(s1 []RingElement, s2 []RingElement) {
	if len(s1) != l44 || len(s2) != k44 {
		panic("mldsa: FVec44.Round expects len(s1)==L44, len(s2)==K44")
	}
	for i := 0; i < l44+k44; i++ {
		for j := 0; j < n; j++ {
			u := int32(math.Round(v[i*n+j]))
			t := u >> 31
			u += t & q
			if u >= q {
				u -= q
			}
			if i < l44 {
				s1[i][j] = fieldElement(u)
			} else {
				s2[i-l44][j] = fieldElement(u)
			}
		}
	}
}

// Excess reports whether the ν-scaled L2 norm of v exceeds r. The first L44
// polynomial-worths of coefficients are treated as ν-scaled and re-divided
// by ν² before accumulation, mirroring the threshold-Dilithium hyperball.
func (v *FVec44) Excess(r, nu float64) bool {
	var sq float64
	for i := 0; i < l44+k44; i++ {
		for j := 0; j < n; j++ {
			val := v[i*n+j]
			if i < l44 {
				sq += val * val / (nu * nu)
			} else {
				sq += val * val
			}
		}
	}
	return sq > r*r
}

// SampleHyperball44 fills p with a point uniformly distributed in a ν-scaled
// L2 ball of radius r, using SHAKE256 seeded by rhop and nonce. Implements
// the Box-Muller-based hyperball sampler from ePrint 2025/1166 §4.
//
// Note: uses math.Sqrt/Log/Cos/Sin (float64). This is an academic prototype
// primitive and is not side-channel resistant.
func SampleHyperball44(p *FVec44, r, nu float64, rhop [64]byte, nonce uint16) {
	total := n*(k44+l44) + 2
	buf := make([]byte, total*8)
	h := sha3.NewSHAKE256()
	h.Write([]byte("H")) // domain separator
	h.Write(rhop[:])
	var iv [2]byte
	iv[0] = byte(nonce)
	iv[1] = byte(nonce >> 8)
	h.Write(iv[:])
	h.Read(buf)

	samples := make([]float64, total)
	var sq float64
	for i := 0; i < total; i += 2 {
		u1 := binary.LittleEndian.Uint64(buf[i*8 : (i+1)*8])
		u2 := binary.LittleEndian.Uint64(buf[(i+1)*8 : (i+2)*8])
		f1 := float64(u1) / (1 << 64)
		f2 := float64(u2) / (1 << 64)
		rad := math.Sqrt(-2 * math.Log(f1))
		z1 := rad * math.Cos(2*math.Pi*f2)
		z2 := rad * math.Sin(2*math.Pi*f2)
		samples[i] = z1
		samples[i+1] = z2
		sq += z1*z1 + z2*z2
		if i < n*l44 {
			samples[i] *= nu
			samples[i+1] *= nu
		}
	}
	factor := r / math.Sqrt(sq)
	for i := 0; i < n*(l44+k44); i++ {
		p[i] = samples[i] * factor
	}
}
