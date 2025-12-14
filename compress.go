package mldsa

// power2Round decomposes r into (r1, r0) such that r = r1 * 2^d + r0 mod q.
// Returns r1 (high bits) and r0 (low bits in centered representation).
// Implements FIPS 204 Algorithm 35.
func power2Round(r fieldElement) (r1, r0 fieldElement) {
	r1 = r >> d
	r0 = r - r1<<d

	const half = 1 << (d - 1) // 4096

	// If r0 > half, adjust to centered representation
	if r0 > half {
		r0 = fieldSub(r0, 1<<d)
		r1++
	}
	return r1, r0
}

// highBits extracts the high-order bits of r after decomposition by 2*gamma2.
// Implements FIPS 204 Algorithm 37 (HighBits).
func highBits(r fieldElement, gamma2 uint32) uint32 {
	r1 := int32((r + 127) >> 7)

	if gamma2 == gamma2QMinus1Div32 {
		// gamma2 = (q-1)/32 = 261888
		// Returns ((ceil(r / 128) * 1025 + 2^21) / 2^22) mod 16
		r1 = (r1*1025 + (1 << 21)) >> 22
		return uint32(r1) & 15
	}
	// gamma2 = (q-1)/88 = 95232
	r1 = (r1*11275 + (1 << 23)) >> 24
	// Ensure r1 < 44
	r1 ^= ((43 - r1) >> 31) & r1
	return uint32(r1)
}

// decompose splits r into (r1, r0) where r = r1 * 2*gamma2 + r0.
// r1 = HighBits(r), r0 = LowBits(r) in signed representation.
// Implements FIPS 204 Algorithm 36, 37, 38.
func decompose(r fieldElement, gamma2 uint32) (r1 uint32, r0 int32) {
	r1 = highBits(r, gamma2)
	r0 = int32(r) - int32(r1)*int32(gamma2)*2
	// Center r0
	r0 -= ((int32(qMinus1Div2) - r0) >> 31) & q
	return r1, r0
}

// makeHint computes the hint bit for a single coefficient.
// Returns 1 if HighBits(r+z) != HighBits(r), 0 otherwise.
// Implements FIPS 204 Algorithm 39.
func makeHint(z, r fieldElement, gamma2 uint32) fieldElement {
	r0 := fieldAdd(r, z)
	if highBits(r0, gamma2) != highBits(r, gamma2) {
		return 1
	}
	return 0
}

// useHint uses the hint to recover the correct high bits.
// Implements FIPS 204 Algorithm 40.
func useHint(hint, r fieldElement, gamma2 uint32) fieldElement {
	r1, r0 := decompose(r, gamma2)
	if hint == 0 {
		return fieldElement(r1)
	}

	if gamma2 == gamma2QMinus1Div32 {
		// m = 16
		if r0 > 0 {
			return fieldElement((r1 + 1) & 15)
		}
		return fieldElement((r1 - 1) & 15)
	}
	// m = 44 for gamma2 = (q-1)/88
	if r0 > 0 {
		if r1 == 43 {
			return 0
		}
		return fieldElement(r1 + 1)
	}
	if r1 == 0 {
		return 43
	}
	return fieldElement(r1 - 1)
}

// infinityNorm computes |a|, where a is interpreted as signed mod q.
// Returns min(a, q-a).
func infinityNorm(a fieldElement) uint32 {
	if uint32(a) <= qMinus1Div2 {
		return uint32(a)
	}
	return q - uint32(a)
}

// polyInfinityNorm returns the maximum absolute value of any coefficient.
func polyInfinityNorm[T ~[n]fieldElement](f T) uint32 {
	var max uint32
	for i := range f {
		v := infinityNorm(f[i])
		if v > max {
			max = v
		}
	}
	return max
}

// vectorInfinityNorm returns the maximum infinity norm across a vector of polynomials.
func vectorInfinityNorm[T ~[n]fieldElement](v []T) uint32 {
	var max uint32
	for i := range v {
		norm := polyInfinityNorm(v[i])
		if norm > max {
			max = norm
		}
	}
	return max
}

// vectorInfinityNormSigned returns the max norm for signed int32 arrays.
func vectorInfinityNormSigned(v [][n]int32) int32 {
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

// countOnes counts the number of non-zero coefficients in a vector.
func countOnes[T ~[n]fieldElement](v []T) int {
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
