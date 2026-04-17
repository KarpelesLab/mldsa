package mldsa

import (
	"crypto/sha3"
)

// SampleNTTPoly generates a uniformly random polynomial in NTT domain
// using rejection sampling from SHAKE128 output.
// Implements FIPS 204 Algorithm 30 (RejNTTPoly).
func SampleNTTPoly(rho []byte, s, r byte) NttElement {
	h := sha3.NewSHAKE128()
	h.Write(rho)
	h.Write([]byte{s, r})

	var buf [168]byte // SHAKE128 rate
	var a NttElement
	j := 0

	for {
		h.Read(buf[:])
		for i := 0; i < len(buf) && j < N; i += 3 {
			// Extract 24 bits, mask to 23 bits
			v := uint32(buf[i]) | uint32(buf[i+1])<<8 | (uint32(buf[i+2])&0x7f)<<16
			if v < Q {
				a[j] = FieldElement(v)
				j++
			}
		}
		if j >= N {
			return a
		}
	}
}

// SampleBoundedPoly generates a polynomial with coefficients in [-eta, eta]
// using rejection sampling from SHAKE256 output.
// Implements FIPS 204 Algorithm 31 (RejBoundedPoly).
func SampleBoundedPoly(seed []byte, eta int, nonce uint16) RingElement {
	h := sha3.NewSHAKE256()
	h.Write(seed)
	h.Write([]byte{byte(nonce), byte(nonce >> 8)})

	var buf [136]byte // SHAKE256 rate
	var a RingElement
	j := 0
	offset := 0

	h.Read(buf[:])

	for j < N {
		if offset >= len(buf) {
			h.Read(buf[:])
			offset = 0
		}

		z0 := buf[offset] & 0x0f
		z1 := buf[offset] >> 4
		offset++

		if eta == 2 {
			// For eta=2: valid values are 0-4 (mapped to 2,1,0,-1,-2)
			if z0 < 15 {
				z0 = z0 - (z0/5)*5 // z0 mod 5
				a[j] = fieldSub(2, FieldElement(z0))
				j++
			}
			if j < N && z1 < 15 {
				z1 = z1 - (z1/5)*5 // z1 mod 5
				a[j] = fieldSub(2, FieldElement(z1))
				j++
			}
		} else { // eta == 4
			// For eta=4: valid values are 0-8 (mapped to 4,3,2,1,0,-1,-2,-3,-4)
			if z0 <= 8 {
				a[j] = fieldSub(4, FieldElement(z0))
				j++
			}
			if j < N && z1 <= 8 {
				a[j] = fieldSub(4, FieldElement(z1))
				j++
			}
		}
	}
	return a
}

// SampleChallenge generates the challenge polynomial c with tau non-zero
// coefficients in {-1, 1}. Uses Fisher-Yates shuffle.
// Implements FIPS 204 Algorithm 29 (SampleInBall).
func SampleChallenge(seed []byte, tau int) RingElement {
	h := sha3.NewSHAKE256()
	h.Write(seed)

	var buf [136]byte
	h.Read(buf[:])

	// First 8 bytes encode sign bits
	var signs uint64
	for i := 0; i < 8; i++ {
		signs |= uint64(buf[i]) << (8 * i)
	}
	offset := 8

	var c RingElement
	for i := N - tau; i < N; i++ {
		// Sample j uniformly from [0, i]
		var j byte
		for {
			if offset >= len(buf) {
				h.Read(buf[:])
				offset = 0
			}
			j = buf[offset]
			offset++
			if int(j) <= i {
				break
			}
		}

		// Swap c[i] and c[j], then set c[j] to ±1
		c[i] = c[j]
		if signs&1 == 0 {
			c[j] = 1
		} else {
			c[j] = Q - 1 // -1 mod Q
		}
		signs >>= 1
	}
	return c
}

// ExpandMask generates a polynomial with coefficients in [-gamma1+1, gamma1].
// Implements FIPS 204 Algorithm 34 (ExpandMask).
func ExpandMask(seed []byte, gamma1Bits int) RingElement {
	h := sha3.NewSHAKE256()
	h.Write(seed)

	var f RingElement
	if gamma1Bits == 17 {
		// 18 bits per coefficient, 256 coefficients = 576 bytes
		var buf [576]byte
		h.Read(buf[:])
		unpackZ17Into(buf[:], &f)
	} else { // gamma1Bits == 19
		// 20 bits per coefficient, 256 coefficients = 640 bytes
		var buf [640]byte
		h.Read(buf[:])
		unpackZ19Into(buf[:], &f)
	}
	return f
}

// unpackZ17Into unpacks 256 coefficients encoded as 18-bit signed values.
func unpackZ17Into(b []byte, f *RingElement) {
	const gamma1 = 1 << 17
	const mask = (1 << 18) - 1
	for i := 0; i < N; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		f[i] = fieldSub(FieldElement(gamma1), FieldElement(x&mask))
		f[i+1] = fieldSub(FieldElement(gamma1), FieldElement((x>>18)&mask))
		f[i+2] = fieldSub(FieldElement(gamma1), FieldElement((x>>36)&mask))
		// Last 10 bits from x, first 8 bits from b[8]
		x2 := uint64(b[8])
		f[i+3] = fieldSub(FieldElement(gamma1), FieldElement(((x>>54)|(x2<<10))&mask))
		b = b[9:]
	}
}

// unpackZ19Into unpacks 256 coefficients encoded as 20-bit signed values.
func unpackZ19Into(b []byte, f *RingElement) {
	const gamma1 = 1 << 19
	const mask = (1 << 20) - 1
	for i := 0; i < N; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		f[i] = fieldSub(FieldElement(gamma1), FieldElement(x&mask))
		f[i+1] = fieldSub(FieldElement(gamma1), FieldElement((x>>20)&mask))
		f[i+2] = fieldSub(FieldElement(gamma1), FieldElement((x>>40)&mask))
		// Last 4 bits from x, first 16 bits from next bytes
		x2 := uint64(b[8]) | uint64(b[9])<<8
		f[i+3] = fieldSub(FieldElement(gamma1), FieldElement(((x>>60)|(x2<<4))&mask))
		b = b[10:]
	}
}
