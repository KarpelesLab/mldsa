package mldsa

import "errors"

// packT1 packs a polynomial with 10-bit coefficients (for public key t1).
// Each coefficient is in [0, 2^10).
func packT1(f ringElement) []byte {
	b := make([]byte, encodingSize10)
	for i := 0; i < n; i += 4 {
		x := uint64(f[i]) | uint64(f[i+1])<<10 | uint64(f[i+2])<<20 | uint64(f[i+3])<<30
		b[i/4*5] = byte(x)
		b[i/4*5+1] = byte(x >> 8)
		b[i/4*5+2] = byte(x >> 16)
		b[i/4*5+3] = byte(x >> 24)
		b[i/4*5+4] = byte(x >> 32)
	}
	return b
}

// unpackT1 unpacks a polynomial with 10-bit coefficients.
func unpackT1(b []byte) ringElement {
	var f ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		f[i] = fieldElement(x & 0x3FF)
		f[i+1] = fieldElement((x >> 10) & 0x3FF)
		f[i+2] = fieldElement((x >> 20) & 0x3FF)
		f[i+3] = fieldElement((x >> 30) & 0x3FF)
		b = b[5:]
	}
	return f
}

// packT0 packs a polynomial with 13-bit signed coefficients (for private key t0).
// Coefficients are in [-(2^12-1), 2^12].
func packT0(f ringElement) []byte {
	b := make([]byte, encodingSize13)
	const center = 1 << 12 // 4096
	idx := 0
	for i := 0; i < n; i += 8 {
		// Pack 8 coefficients into 13 bytes
		var x1, x2 uint64
		x1 = uint64(fieldSub(center, f[i]))
		x1 |= uint64(fieldSub(center, f[i+1])) << 13
		x1 |= uint64(fieldSub(center, f[i+2])) << 26
		x1 |= uint64(fieldSub(center, f[i+3])) << 39
		a := uint64(fieldSub(center, f[i+4]))
		x1 |= a << 52
		x2 = a >> 12
		x2 |= uint64(fieldSub(center, f[i+5])) << 1
		x2 |= uint64(fieldSub(center, f[i+6])) << 14
		x2 |= uint64(fieldSub(center, f[i+7])) << 27

		b[idx] = byte(x1)
		b[idx+1] = byte(x1 >> 8)
		b[idx+2] = byte(x1 >> 16)
		b[idx+3] = byte(x1 >> 24)
		b[idx+4] = byte(x1 >> 32)
		b[idx+5] = byte(x1 >> 40)
		b[idx+6] = byte(x1 >> 48)
		b[idx+7] = byte(x1 >> 56)
		b[idx+8] = byte(x2)
		b[idx+9] = byte(x2 >> 8)
		b[idx+10] = byte(x2 >> 16)
		b[idx+11] = byte(x2 >> 24)
		b[idx+12] = byte(x2 >> 32)
		idx += 13
	}
	return b
}

// unpackT0 unpacks a polynomial with 13-bit signed coefficients.
func unpackT0(b []byte) ringElement {
	var f ringElement
	const center = 1 << 12
	const mask = (1 << 13) - 1
	for i := 0; i < n; i += 8 {
		x1 := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		x2 := uint64(b[8]) | uint64(b[9])<<8 | uint64(b[10])<<16 | uint64(b[11])<<24 | uint64(b[12])<<32
		b = b[13:]

		f[i] = fieldSub(center, fieldElement(x1&mask))
		f[i+1] = fieldSub(center, fieldElement((x1>>13)&mask))
		f[i+2] = fieldSub(center, fieldElement((x1>>26)&mask))
		f[i+3] = fieldSub(center, fieldElement((x1>>39)&mask))
		f[i+4] = fieldSub(center, fieldElement(((x1>>52)|(x2<<12))&mask))
		f[i+5] = fieldSub(center, fieldElement((x2>>1)&mask))
		f[i+6] = fieldSub(center, fieldElement((x2>>14)&mask))
		f[i+7] = fieldSub(center, fieldElement((x2>>27)&mask))
	}
	return f
}

// packEta2 packs a polynomial with coefficients in [-2, 2] using 3 bits each.
func packEta2(f ringElement) []byte {
	b := make([]byte, encodingSize3)
	for i := 0; i < n; i += 8 {
		var x uint32
		for j := 0; j < 8; j++ {
			x |= uint32(fieldSub(2, f[i+j])) << (3 * j)
		}
		b[i/8*3] = byte(x)
		b[i/8*3+1] = byte(x >> 8)
		b[i/8*3+2] = byte(x >> 16)
	}
	return b
}

// unpackEta2 unpacks a polynomial with coefficients in [-2, 2].
func unpackEta2(b []byte) (ringElement, error) {
	var f ringElement
	for i := 0; i < n; i += 8 {
		x := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		// Check for invalid values (>= 5 in any nibble)
		msbs := x & 0o44444444 // octal: select MSB of each 3-bit group
		mask := (msbs >> 1) | (msbs >> 2)
		if mask&x != 0 {
			return ringElement{}, errors.New("mldsa: invalid eta encoding")
		}
		b = b[3:]
		for j := 0; j < 8; j++ {
			f[i+j] = fieldSub(2, fieldElement((x>>(3*j))&0x7))
		}
	}
	return f, nil
}

// packEta4 packs a polynomial with coefficients in [-4, 4] using 4 bits each.
func packEta4(f ringElement) []byte {
	b := make([]byte, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[i/2] = byte(fieldSub(4, f[i])) | byte(fieldSub(4, f[i+1]))<<4
	}
	return b
}

// unpackEta4 unpacks a polynomial with coefficients in [-4, 4].
func unpackEta4(b []byte) (ringElement, error) {
	var f ringElement
	for i := 0; i < n; i += 8 {
		x := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		// Check for invalid values (>= 9 in any nibble)
		msbs := x & 0x88888888
		mask := (msbs >> 1) | (msbs >> 2) | (msbs >> 3)
		if mask&x != 0 {
			return ringElement{}, errors.New("mldsa: invalid eta encoding")
		}
		b = b[4:]
		for j := 0; j < 8; j++ {
			f[i+j] = fieldSub(4, fieldElement((x>>(4*j))&0xF))
		}
	}
	return f, nil
}

// packZ17 packs a polynomial z with coefficients in [-(gamma1-1), gamma1]
// where gamma1 = 2^17. Uses 18 bits per coefficient.
func packZ17(f ringElement) []byte {
	b := make([]byte, encodingSize18)
	const gamma1 = 1 << 17
	idx := 0
	for i := 0; i < n; i += 4 {
		var x1, x2 uint64
		x1 = uint64(fieldSub(gamma1, f[i]))
		x1 |= uint64(fieldSub(gamma1, f[i+1])) << 18
		x1 |= uint64(fieldSub(gamma1, f[i+2])) << 36
		x2 = uint64(fieldSub(gamma1, f[i+3]))
		x1 |= x2 << 54
		x2 >>= 10

		b[idx] = byte(x1)
		b[idx+1] = byte(x1 >> 8)
		b[idx+2] = byte(x1 >> 16)
		b[idx+3] = byte(x1 >> 24)
		b[idx+4] = byte(x1 >> 32)
		b[idx+5] = byte(x1 >> 40)
		b[idx+6] = byte(x1 >> 48)
		b[idx+7] = byte(x1 >> 56)
		b[idx+8] = byte(x2)
		idx += 9
	}
	return b
}

// unpackZ17 unpacks a polynomial z packed with packZ17.
func unpackZ17Sig(b []byte) ringElement {
	var f ringElement
	const gamma1 = 1 << 17
	const mask = (1 << 18) - 1
	for i := 0; i < n; i += 4 {
		x1 := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		x2 := uint64(b[8])
		b = b[9:]
		f[i] = fieldSub(gamma1, fieldElement(x1&mask))
		f[i+1] = fieldSub(gamma1, fieldElement((x1>>18)&mask))
		f[i+2] = fieldSub(gamma1, fieldElement((x1>>36)&mask))
		f[i+3] = fieldSub(gamma1, fieldElement(((x1>>54)|(x2<<10))&mask))
	}
	return f
}

// packZ19 packs a polynomial z with coefficients in [-(gamma1-1), gamma1]
// where gamma1 = 2^19. Uses 20 bits per coefficient.
func packZ19(f ringElement) []byte {
	b := make([]byte, encodingSize20)
	const gamma1 = 1 << 19
	idx := 0
	for i := 0; i < n; i += 4 {
		var x1, x2 uint64
		x1 = uint64(fieldSub(gamma1, f[i]))
		x1 |= uint64(fieldSub(gamma1, f[i+1])) << 20
		x1 |= uint64(fieldSub(gamma1, f[i+2])) << 40
		x2 = uint64(fieldSub(gamma1, f[i+3]))
		x1 |= x2 << 60
		x2 >>= 4

		b[idx] = byte(x1)
		b[idx+1] = byte(x1 >> 8)
		b[idx+2] = byte(x1 >> 16)
		b[idx+3] = byte(x1 >> 24)
		b[idx+4] = byte(x1 >> 32)
		b[idx+5] = byte(x1 >> 40)
		b[idx+6] = byte(x1 >> 48)
		b[idx+7] = byte(x1 >> 56)
		b[idx+8] = byte(x2)
		b[idx+9] = byte(x2 >> 8)
		idx += 10
	}
	return b
}

// unpackZ19 unpacks a polynomial z packed with packZ19.
func unpackZ19Sig(b []byte) ringElement {
	var f ringElement
	const gamma1 = 1 << 19
	const mask = (1 << 20) - 1
	for i := 0; i < n; i += 4 {
		x1 := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		x2 := uint64(b[8]) | uint64(b[9])<<8
		b = b[10:]
		f[i] = fieldSub(gamma1, fieldElement(x1&mask))
		f[i+1] = fieldSub(gamma1, fieldElement((x1>>20)&mask))
		f[i+2] = fieldSub(gamma1, fieldElement((x1>>40)&mask))
		f[i+3] = fieldSub(gamma1, fieldElement(((x1>>60)|(x2<<4))&mask))
	}
	return f
}

// packW1_4 packs w1 with 4-bit coefficients (for ML-DSA-65/87).
func packW1_4(f ringElement) []byte {
	b := make([]byte, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[i/2] = byte(f[i]) | byte(f[i+1])<<4
	}
	return b
}

// packW1_6 packs w1 with 6-bit coefficients (for ML-DSA-44).
func packW1_6(f ringElement) []byte {
	b := make([]byte, encodingSize6)
	for i := 0; i < n; i += 4 {
		x := uint32(f[i]) | uint32(f[i+1])<<6 | uint32(f[i+2])<<12 | uint32(f[i+3])<<18
		b[i/4*3] = byte(x)
		b[i/4*3+1] = byte(x >> 8)
		b[i/4*3+2] = byte(x >> 16)
	}
	return b
}

// packHint packs the hint vector into a byte slice.
func packHint[T ~[n]fieldElement](hints []T, omega int) []byte {
	k := len(hints)
	b := make([]byte, omega+k)
	idx := 0
	for i := 0; i < k; i++ {
		for j := 0; j < n; j++ {
			if hints[i][j] != 0 {
				b[idx] = byte(j)
				idx++
			}
		}
		b[omega+i] = byte(idx)
	}
	return b
}

// unpackHint unpacks the hint vector from a byte slice.
func unpackHint[T ~[n]fieldElement](b []byte, hints []T, omega int) bool {
	k := len(hints)
	idx := 0
	for i := 0; i < k; i++ {
		limit := int(b[omega+i])
		if limit < idx || limit > omega {
			return false
		}
		prev := idx
		for ; idx < limit; idx++ {
			pos := b[idx]
			// Check strictly increasing order
			if idx > prev && b[idx-1] >= pos {
				return false
			}
			hints[i][pos] = 1
		}
	}
	// Remaining bytes must be zero
	for ; idx < omega; idx++ {
		if b[idx] != 0 {
			return false
		}
	}
	return true
}
