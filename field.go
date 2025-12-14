package mldsa

// fieldElement is an integer modulo q, always in reduced form [0, q).
type fieldElement uint32

// ringElement is a polynomial with n coefficients in Z_q.
type ringElement [n]fieldElement

// nttElement is the NTT representation of a polynomial.
type nttElement [n]fieldElement

// Montgomery form constants.
const (
	// qInv = q^(-1) mod 2^32
	qInv = 58728449
	// qNegInv = -q^(-1) mod 2^32 = 2^32 - qInv*q mod 2^32
	qNegInv = 4236238847
	// montR = 2^32 mod q (Montgomery R)
	montR = 4193792
	// montR2 = 2^64 mod q (Montgomery R^2)
	montR2 = 2365951
	// invN = n^(-1) * R^2 mod q (for inverse NTT scaling)
	invN = 41978
)

// fieldReduceOnce reduces a value < 2q to [0, q).
func fieldReduceOnce(a uint32) fieldElement {
	// If a >= q, subtract q
	x := a - q
	// If underflow (a < q), x has high bit set
	x += (x >> 31) * q
	return fieldElement(x)
}

// fieldAdd returns (a + b) mod q.
func fieldAdd(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint32(a) + uint32(b))
}

// fieldSub returns (a - b) mod q.
func fieldSub(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint32(a) - uint32(b) + q)
}

// fieldReduce performs Montgomery reduction: returns a * R^(-1) mod q
// where a < q * 2^32.
func fieldReduce(a uint64) fieldElement {
	// Montgomery reduction: t = ((a mod 2^32) * qNegInv) mod 2^32
	t := uint32(a) * qNegInv
	// result = (a + t*q) / 2^32
	return fieldReduceOnce(uint32((a + uint64(t)*q) >> 32))
}

// fieldMul returns (a * b) mod q using Montgomery multiplication.
// Both inputs and output are in Montgomery form.
func fieldMul(a, b fieldElement) fieldElement {
	return fieldReduce(uint64(a) * uint64(b))
}

// polyAdd adds two polynomials coefficient-wise.
func polyAdd[T ~[n]fieldElement](a, b T) (c T) {
	for i := range c {
		c[i] = fieldAdd(a[i], b[i])
	}
	return c
}

// polySub subtracts two polynomials coefficient-wise.
func polySub[T ~[n]fieldElement](a, b T) (c T) {
	for i := range c {
		c[i] = fieldSub(a[i], b[i])
	}
	return c
}
