package mldsa

// Threshold-ML-DSA primitives.
//
// This file exposes the building blocks specific to threshold ML-DSA
// implementations (e.g. github.com/KarpelesLab/tss-lib/v2/mldsatss, based
// on "Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with
// Identifiable Aborts", Borin, Celi, del Pino, Espitau, Niot, Prest
// [ePrint 2025/1166]).
//
// The core ring, NTT, sampling, packing and decomposition primitives used
// by threshold ML-DSA are exported directly from the rest of the package
// (see field.go, ntt.go, sample.go, encode.go, compress.go). Only items
// that are truly threshold-specific, or that require a mode-specific
// specialization of a generic primitive, live here.
//
// WARNING: The threshold surface is research-grade and is NOT stable.
// It is intended for experimentation and prototype integration, not for
// production use.

import (
	"crypto/sha3"
	"encoding/binary"
	"math"
)

// PackPolyQSize is the size of a packed full-range (23-bit) polynomial.
// Used for threshold w commitments, where w values span all of Z_q.
const PackPolyQSize = N * 23 / 8 // 736 bytes

// --- Decomposition & hints specialized for ML-DSA-44 -----------------------

// Decompose44 splits r using γ₂ = (Q-1)/88 (ML-DSA-44).
func Decompose44(r FieldElement) (uint32, int32) { return Decompose(r, Gamma2QMinus1Div88) }

// HighBits44 returns HighBits(r) with γ₂ = (Q-1)/88 (ML-DSA-44).
func HighBits44(r FieldElement) uint32 { return HighBits(r, Gamma2QMinus1Div88) }

// MakeHint44 computes the hint bit with γ₂ = (Q-1)/88 (ML-DSA-44).
func MakeHint44(z, r FieldElement) FieldElement { return MakeHint(z, r, Gamma2QMinus1Div88) }

// UseHint44 recovers high bits using the hint with γ₂ = (Q-1)/88 (ML-DSA-44).
func UseHint44(h, r FieldElement) FieldElement { return UseHint(h, r, Gamma2QMinus1Div88) }

// --- Samplers specialized for ML-DSA-44 ------------------------------------

// SampleA returns A[i][j] in NTT form, derived from rho as in FIPS 204 ExpandA.
// It is a convenience over SampleNTTPoly that takes int indices instead of bytes.
func SampleA(rho []byte, i, j int) NttElement {
	return SampleNTTPoly(rho, byte(j), byte(i))
}

// SampleInBall44 derives the challenge polynomial c with τ=39 non-zero
// coefficients in {-1, 1} (FIPS 204 Algorithm 29, ML-DSA-44).
func SampleInBall44(seed []byte) RingElement { return SampleChallenge(seed, Tau39) }

// ExpandMask17 derives a single polynomial with coefficients in [-γ₁+1, γ₁]
// where γ₁ = 2^17 (ML-DSA-44 nonce layout).
func ExpandMask17(seed []byte) RingElement { return ExpandMask(seed, Gamma1Bits17) }

// --- Packing specialized for ML-DSA-44 -------------------------------------

// PackW1_44 packs w1 with 6-bit coefficients (ML-DSA-44).
func PackW1_44(f RingElement) []byte { return PackW1_6(f) }

// PackHint44 packs the hint vector with ω = 80 (ML-DSA-44).
func PackHint44(v []RingElement) []byte { return PackHint(v, Omega80) }

// UnpackHint44 unpacks the hint vector with ω = 80 (ML-DSA-44). Returns false
// if the encoding is malformed.
func UnpackHint44(b []byte, v []RingElement) bool { return UnpackHint(b, v, Omega80) }

// --- Full-range Z_q polynomial packing -------------------------------------

// PackPolyQ packs a full-range polynomial with 23-bit coefficients into b.
// Used for threshold w commitments, where w values span all of Z_q.
// len(b) must be at least PackPolyQSize. Coefficients must already be in [0, Q).
func PackPolyQ(f RingElement, b []byte) {
	var bitBuf uint64
	var bitLen uint
	bIdx := 0
	for i := 0; i < N; i++ {
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
	for i := 0; i < N; i++ {
		for bitLen < 23 {
			bitBuf |= uint64(b[bIdx]) << bitLen
			bIdx++
			bitLen += 8
		}
		f[i] = FieldElement(bitBuf & ((1 << 23) - 1))
		bitBuf >>= 23
		bitLen -= 23
	}
	return f
}

// --- FVec (float vector for hyperball sampling) ----------------------------

// FVec44 is a float64 vector of L+K polynomials × N coefficients used by
// threshold ML-DSA-44 rejection sampling (see ePrint 2025/1166).
type FVec44 [N * (K44 + L44)]float64

// Add sets v to w + u coefficient-wise.
func (v *FVec44) Add(w, u *FVec44) {
	for i := range v {
		v[i] = w[i] + u[i]
	}
}

// From loads (s1, s2) into v, recentering each coefficient modulo Q into
// (-Q/2, Q/2] before converting to float64. Requires len(s1) == L44 and
// len(s2) == K44.
func (v *FVec44) From(s1 []RingElement, s2 []RingElement) {
	if len(s1) != L44 || len(s2) != K44 {
		panic("mldsa: FVec44.From expects len(s1)==L44, len(s2)==K44")
	}
	for i := 0; i < L44+K44; i++ {
		var poly RingElement
		if i < L44 {
			poly = s1[i]
		} else {
			poly = s2[i-L44]
		}
		for j := 0; j < N; j++ {
			u := int32(poly[j])
			u += Q / 2
			t := u - Q
			u = t + (t>>31)&Q
			u -= Q / 2
			v[i*N+j] = float64(u)
		}
	}
}

// Round writes the rounded, mod-Q-normalized integer value of v back into
// (s1, s2). Requires len(s1) == L44 and len(s2) == K44.
func (v *FVec44) Round(s1 []RingElement, s2 []RingElement) {
	if len(s1) != L44 || len(s2) != K44 {
		panic("mldsa: FVec44.Round expects len(s1)==L44, len(s2)==K44")
	}
	for i := 0; i < L44+K44; i++ {
		for j := 0; j < N; j++ {
			u := int32(math.Round(v[i*N+j]))
			t := u >> 31
			u += t & Q
			if u >= Q {
				u -= Q
			}
			if i < L44 {
				s1[i][j] = FieldElement(u)
			} else {
				s2[i-L44][j] = FieldElement(u)
			}
		}
	}
}

// Excess reports whether the ν-scaled L2 norm of v exceeds r. The first L44
// polynomial-worths of coefficients are treated as ν-scaled and re-divided
// by ν² before accumulation, mirroring the threshold-Dilithium hyperball.
func (v *FVec44) Excess(r, nu float64) bool {
	var sq float64
	for i := 0; i < L44+K44; i++ {
		for j := 0; j < N; j++ {
			val := v[i*N+j]
			if i < L44 {
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
	total := N*(K44+L44) + 2
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
		if i < N*L44 {
			samples[i] *= nu
			samples[i+1] *= nu
		}
	}
	factor := r / math.Sqrt(sq)
	for i := 0; i < N*(L44+K44); i++ {
		p[i] = samples[i] * factor
	}
}
