package mldsa

import (
	"bytes"
	"math"
	"testing"
)

func TestPackPolyQRoundtrip(t *testing.T) {
	var f RingElement
	for i := range f {
		f[i] = FieldElement((uint32(i)*97 + 17) % Q)
	}
	buf := make([]byte, PackPolyQSize)
	PackPolyQ(f, buf)
	g := UnpackPolyQ(buf)
	if g != f {
		t.Fatalf("PackPolyQ/UnpackPolyQ roundtrip mismatch")
	}

	var zero RingElement
	buf2 := make([]byte, PackPolyQSize)
	PackPolyQ(zero, buf2)
	if !bytes.Equal(make([]byte, PackPolyQSize), buf2) {
		t.Fatalf("PackPolyQ(0) should produce all-zero bytes")
	}
	if UnpackPolyQ(buf2) != zero {
		t.Fatalf("UnpackPolyQ(0) should produce zero polynomial")
	}
}

func TestFVec44FromRound(t *testing.T) {
	var f FVec44
	// fill with some values in [-Q/2, Q/2]
	for i := range f {
		f[i] = float64((int(i)*31+7)%Q) - float64(Q/2)
	}
	var s1 [L44]RingElement
	var s2 [K44]RingElement
	f.Round(s1[:], s2[:])

	var g FVec44
	g.From(s1[:], s2[:])
	// Round-trip should be identity modulo Q (within integer precision).
	// Because values were already centered and integer-valued, this should
	// produce exactly the original values.
	for i := range f {
		if g[i] != f[i] {
			t.Fatalf("FVec44 From/Round mismatch at %d: got %v want %v", i, g[i], f[i])
		}
	}
}

func TestFVec44Excess(t *testing.T) {
	var f FVec44
	// All zero — norm is 0, should not exceed any positive r.
	if f.Excess(1.0, 3.0) {
		t.Fatalf("empty FVec should not exceed")
	}
	// Put a single 10 in the K part.
	f[N*L44] = 10
	// nu-scaled L2 is 10 (K part unscaled).
	if f.Excess(9.0, 3.0) != true {
		t.Fatalf("FVec with K-part value 10 must exceed 9")
	}
	if f.Excess(11.0, 3.0) != false {
		t.Fatalf("FVec with K-part value 10 must not exceed 11")
	}
	// Put a value in the L part (nu-scaled). L-part norm = val/nu.
	var g FVec44
	g[0] = 30 // L-part, treated as 30/3 = 10
	if g.Excess(9.0, 3.0) != true {
		t.Fatalf("FVec with L-part value 30 (nu=3) must exceed 9")
	}
	if g.Excess(11.0, 3.0) != false {
		t.Fatalf("FVec with L-part value 30 (nu=3) must not exceed 11")
	}
}

func TestSampleHyperball44Deterministic(t *testing.T) {
	var rhop [64]byte
	for i := range rhop {
		rhop[i] = byte(i)
	}
	var a, b FVec44
	SampleHyperball44(&a, 252778.0, 3.0, rhop, 0)
	SampleHyperball44(&b, 252778.0, 3.0, rhop, 0)
	if a != b {
		t.Fatalf("SampleHyperball44 must be deterministic for fixed seed/nonce")
	}

	// ν-scaled L2 norm. The sampler normalizes `sq` over `N*(k+l)+2` Gaussian
	// samples but only returns `N*(k+l)` of them, so the norm is ≤ r and
	// close to r*sqrt(1 - 2/(N*(k+l)+2)) on average.
	var sq float64
	for i := 0; i < N*(K44+L44); i++ {
		v := a[i]
		if i < N*L44 {
			sq += v * v / (3.0 * 3.0)
		} else {
			sq += v * v
		}
	}
	norm := math.Sqrt(sq)
	if norm > 252778.0 {
		t.Fatalf("SampleHyperball44 norm should not exceed r, got %v", norm)
	}
	if norm < 252778.0*0.99 {
		t.Fatalf("SampleHyperball44 norm suspiciously small: %v", norm)
	}
}

func TestPower2RoundReconstructs(t *testing.T) {
	for _, r := range []FieldElement{0, 1, Q / 2, Q - 1, 123456, 7654321} {
		r1, r0 := Power2Round(r)
		rec := (uint32(r1)<<D + uint32(r0)) % Q
		if FieldElement(rec) != r {
			t.Fatalf("Power2Round(%d)=%d,%d reconstructs to %d", r, r1, r0, rec)
		}
	}
}
