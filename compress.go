package mldsa

// Power2Round decomposes r into (r1, r0) such that r = r1 * 2^D + r0 mod Q.
// Returns r1 (high bits) and r0 (low bits in centered representation).
// Implements FIPS 204 Algorithm 35.
func Power2Round(r FieldElement) (r1, r0 FieldElement) {
	r1 = r >> D
	r0 = r - r1<<D

	const half = 1 << (D - 1) // 4096

	// If r0 > half, adjust to centered representation
	if r0 > half {
		r0 = fieldSub(r0, 1<<D)
		r1++
	}
	return r1, r0
}

// HighBits extracts the high-order bits of r after decomposition by 2*gamma2.
// Implements FIPS 204 Algorithm 37 (HighBits).
func HighBits(r FieldElement, gamma2 uint32) uint32 {
	r1 := int32((r + 127) >> 7)

	if gamma2 == Gamma2QMinus1Div32 {
		// gamma2 = (Q-1)/32 = 261888
		// Returns ((ceil(r / 128) * 1025 + 2^21) / 2^22) mod 16
		r1 = (r1*1025 + (1 << 21)) >> 22
		return uint32(r1) & 15
	}
	// gamma2 = (Q-1)/88 = 95232
	r1 = (r1*11275 + (1 << 23)) >> 24
	// Ensure r1 < 44
	r1 ^= ((43 - r1) >> 31) & r1
	return uint32(r1)
}

// Decompose splits r into (r1, r0) where r = r1 * 2*gamma2 + r0.
// r1 = HighBits(r), r0 = LowBits(r) in signed representation.
// Implements FIPS 204 Algorithm 36, 37, 38.
func Decompose(r FieldElement, gamma2 uint32) (r1 uint32, r0 int32) {
	r1 = HighBits(r, gamma2)
	r0 = int32(r) - int32(r1)*int32(gamma2)*2
	// Center r0
	r0 -= ((int32(QMinus1Div2) - r0) >> 31) & Q
	return r1, r0
}

// MakeHint computes the hint bit for a single coefficient.
// Returns 1 if HighBits(r+z) != HighBits(r), 0 otherwise.
// Implements FIPS 204 Algorithm 39.
func MakeHint(z, r FieldElement, gamma2 uint32) FieldElement {
	r0 := fieldAdd(r, z)
	if HighBits(r0, gamma2) != HighBits(r, gamma2) {
		return 1
	}
	return 0
}

// UseHint uses the hint to recover the correct high bits.
// Implements FIPS 204 Algorithm 40.
func UseHint(hint, r FieldElement, gamma2 uint32) FieldElement {
	r1, r0 := Decompose(r, gamma2)
	if hint == 0 {
		return FieldElement(r1)
	}

	if gamma2 == Gamma2QMinus1Div32 {
		// m = 16
		if r0 > 0 {
			return FieldElement((r1 + 1) & 15)
		}
		return FieldElement((r1 - 1) & 15)
	}
	// m = 44 for gamma2 = (Q-1)/88
	if r0 > 0 {
		if r1 == 43 {
			return 0
		}
		return FieldElement(r1 + 1)
	}
	if r1 == 0 {
		return 43
	}
	return FieldElement(r1 - 1)
}

// InfinityNorm computes |a|, where a is interpreted as signed mod Q.
// Returns min(a, Q-a).
func InfinityNorm(a FieldElement) uint32 {
	if uint32(a) <= QMinus1Div2 {
		return uint32(a)
	}
	return Q - uint32(a)
}

// PolyInfinityNorm returns the maximum absolute value of any coefficient.
func PolyInfinityNorm[T ~[N]FieldElement](f T) uint32 {
	var max uint32
	for i := range f {
		v := InfinityNorm(f[i])
		if v > max {
			max = v
		}
	}
	return max
}

// VectorInfinityNorm returns the maximum infinity norm across a vector of polynomials.
func VectorInfinityNorm[T ~[N]FieldElement](v []T) uint32 {
	var max uint32
	for i := range v {
		norm := PolyInfinityNorm(v[i])
		if norm > max {
			max = norm
		}
	}
	return max
}

// vectorInfinityNormSigned returns the max norm for signed int32 arrays.
func vectorInfinityNormSigned(v [][N]int32) int32 {
	var max int32
	for i := range v {
		for j := range v[i] {
			val := v[i][j]
			if val < 0 {
				val = -val
			}
			if val > max {
				max = val
			}
		}
	}
	return max
}

// CountOnes counts the number of non-zero coefficients in a vector.
func CountOnes[T ~[N]FieldElement](v []T) int {
	count := 0
	for i := range v {
		for j := range v[i] {
			if v[i][j] != 0 {
				count++
			}
		}
	}
	return count
}
