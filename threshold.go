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
	"math/bits"
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

// --- Constant-time discrete Gaussian for hyperball sampling ---------------
//
// The hyperball sampler needs a spherically-symmetric distribution whose
// direction, after L2 normalization, is (approximately) uniform on the
// sphere. A discrete Gaussian D_σ over Z fits the bill without any float
// arithmetic on secret-dependent values: sampling reduces to a CDT lookup
// against uniform random bits, which we perform in constant time by
// scanning every table entry regardless of the input.
//
// Parameter choices:
//   σ = 8 gives a CDT small enough (64 entries) to scan per sample cheaply
//     while keeping the tail beyond the representable 64-bit CDT precision.
//     The resulting bias from discretization is O(1/σ) per coordinate and
//     disappears after L2 normalization onto the hyperball.
//   64-bit CDT precision: each entry is floor(2^64 · Pr[|X| ≤ k]). The
//     sampler consumes 8 random bytes for the magnitude lookup plus 1 byte
//     for the sign (LSB), i.e. 9 bytes per sample.

const (
	hyperballSigma          = 8
	hyperballCDTSize        = 64
	hyperballBytesPerSample = 9
)

// hyperballCDT[k] = floor(2^64 · Pr[|X| ≤ k]) for X ~ D_σ over Z.
// Populated at init from math.Exp; the table is an input-independent
// constant, so the non-CT Exp calls here do not affect the SC resistance
// of SampleHyperball44 itself.
var hyperballCDT [hyperballCDTSize]uint64

func init() {
	const sigma2 = float64(hyperballSigma * hyperballSigma)
	const tailExtent = hyperballCDTSize + 16

	var rho float64
	for k := -tailExtent; k <= tailExtent; k++ {
		rho += math.Exp(-float64(k*k) / (2 * sigma2))
	}

	scale := math.Exp2(64)
	var acc float64
	for k := 0; k < hyperballCDTSize; k++ {
		if k == 0 {
			acc = 1.0 / rho
		} else {
			acc += 2 * math.Exp(-float64(k*k)/(2*sigma2)) / rho
		}
		scaled := acc * scale
		switch {
		case scaled >= scale:
			hyperballCDT[k] = math.MaxUint64
		case scaled <= 0:
			hyperballCDT[k] = 0
		default:
			hyperballCDT[k] = uint64(scaled)
		}
	}
}

// ctGeU64 returns 1 if a ≥ b (unsigned), 0 otherwise, in constant time.
func ctGeU64(a, b uint64) uint64 {
	_, borrow := bits.Sub64(a, b, 0)
	return 1 - borrow
}

// ctSampleDGaussian returns a sample from D_σ over Z (σ = hyperballSigma),
// in constant time relative to the input bytes. magBytes supplies the 64
// bits compared against the CDT; signByte's LSB chooses the sign.
func ctSampleDGaussian(magBytes uint64, signByte byte) int32 {
	var k uint64
	for i := 0; i < hyperballCDTSize-1; i++ {
		k += ctGeU64(magBytes, hyperballCDT[i])
	}
	mag := int32(k)
	signMask := -int32(signByte & 1)
	return (mag ^ signMask) - signMask
}

// ctISqrt64 returns floor(sqrt(n)) via branch-free bit-by-bit iteration
// (digit-by-digit method). Runs exactly 32 iterations regardless of n.
func ctISqrt64(n uint64) uint64 {
	var res uint64
	rem := n
	bit := uint64(1) << 62
	for bit != 0 {
		sum := res + bit
		ge := ctGeU64(rem, sum)
		rem -= ge * sum
		res = res>>1 + ge*bit
		bit >>= 2
	}
	return res
}

// ctICeilSqrt64 returns ceil(sqrt(n)). For our use n ≤ ~2^23, so s*s does
// not overflow uint64.
func ctICeilSqrt64(n uint64) uint64 {
	s := ctISqrt64(n)
	adj := ctGeU64(n, s*s+1)
	return s + adj
}

// SampleHyperball44 fills p with a point on the ν-scaled L2 hyperball of
// radius r, deterministically derived from (rhop, nonce) via SHAKE256.
// Implements the hyperball primitive from ePrint 2025/1166 §4, adapted to
// avoid float64 operations on secret-dependent values.
//
// Side-channel posture: all secret-dependent steps (CDT sampling, Σ z_i²,
// integer sqrt) run in constant time. The trailing r / sqrt(sq) float
// division and the float64 multiplications that produce p[i] operate on
// quantities an observer can recover from the public output ‖p‖, so any
// residual float-timing leakage is bounded by what the output itself
// already reveals.
func SampleHyperball44(p *FVec44, r, nu float64, rhop [64]byte, nonce uint16) {
	const total = N*(K44+L44) + 2

	buf := make([]byte, total*hyperballBytesPerSample)
	h := sha3.NewSHAKE256()
	h.Write([]byte("H")) // domain separator
	h.Write(rhop[:])
	h.Write([]byte{byte(nonce), byte(nonce >> 8)})
	h.Read(buf)

	var z [total]int32
	var sq uint64
	for i := 0; i < total; i++ {
		base := i * hyperballBytesPerSample
		magBytes := binary.LittleEndian.Uint64(buf[base : base+8])
		z[i] = ctSampleDGaussian(magBytes, buf[base+8])
		v := int64(z[i])
		sq += uint64(v * v)
	}

	// ceil(sqrt(sq)) guarantees factor ≤ r/||z_total||, so the output norm
	// (over the first N·(K44+L44) samples) is strictly ≤ r.
	isqrt := ctICeilSqrt64(sq)
	factor := r / float64(isqrt)
	scaleL := factor * nu
	scaleK := factor

	for i := 0; i < N*L44; i++ {
		p[i] = float64(z[i]) * scaleL
	}
	for i := N * L44; i < N*(K44+L44); i++ {
		p[i] = float64(z[i]) * scaleK
	}
}
