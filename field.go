package mldsa

// FieldElement is an integer modulo Q, always in reduced form [0, Q).
type FieldElement uint32

// RingElement is a polynomial with N coefficients in Z_q.
type RingElement [N]FieldElement

// NttElement is the NTT representation of a polynomial.
type NttElement [N]FieldElement

// Montgomery form constants.
const (
	// qInv = Q^(-1) mod 2^32
	// qInv = 58728449
	// qNegInv = -Q^(-1) mod 2^32 = 2^32 - qInv*Q mod 2^32
	qNegInv = 4236238847
	// montR = 2^32 mod Q (Montgomery R)
	// montR = 4193792
	// montR2 = 2^64 mod Q (Montgomery R^2)
	// montR2 = 2365951
	// invN = N^(-1) * R^2 mod Q (for inverse NTT scaling)
	invN = 41978
)

// fieldReduceOnce reduces a value < 2q to [0, Q).
func fieldReduceOnce(a uint32) FieldElement {
	// If a >= Q, subtract Q
	x := a - Q
	// If underflow (a < Q), x has high bit set
	x += (x >> 31) * Q
	return FieldElement(x)
}

// fieldAdd returns (a + b) mod Q.
func fieldAdd(a, b FieldElement) FieldElement {
	return fieldReduceOnce(uint32(a) + uint32(b))
}

// fieldSub returns (a - b) mod Q.
func fieldSub(a, b FieldElement) FieldElement {
	return fieldReduceOnce(uint32(a) - uint32(b) + Q)
}

// fieldReduce performs Montgomery reduction: returns a * R^(-1) mod Q
// where a < Q * 2^32.
func fieldReduce(a uint64) FieldElement {
	// Montgomery reduction: t = ((a mod 2^32) * qNegInv) mod 2^32
	t := uint32(a) * qNegInv
	// result = (a + t*Q) / 2^32
	return fieldReduceOnce(uint32((a + uint64(t)*Q) >> 32))
}

// fieldMul returns (a * b) mod Q using Montgomery multiplication.
// Both inputs and output are in Montgomery form.
func fieldMul(a, b FieldElement) FieldElement {
	return fieldReduce(uint64(a) * uint64(b))
}

// PolyAdd adds two polynomials coefficient-wise.
func PolyAdd[T ~[N]FieldElement](a, b T) (c T) {
	for i := range c {
		c[i] = fieldAdd(a[i], b[i])
	}
	return c
}

// PolySub subtracts two polynomials coefficient-wise.
func PolySub[T ~[N]FieldElement](a, b T) (c T) {
	for i := range c {
		c[i] = fieldSub(a[i], b[i])
	}
	return c
}
