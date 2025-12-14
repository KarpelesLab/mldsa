package mldsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKey44(t *testing.T) {
	key, err := GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey44 failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey44 returned nil key")
	}
}

func TestGenerateKey65(t *testing.T) {
	key, err := GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey65 failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey65 returned nil key")
	}
}

func TestGenerateKey87(t *testing.T) {
	key, err := GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey87 failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey87 returned nil key")
	}
}

func TestSignVerify44(t *testing.T) {
	key, err := GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey44 failed: %v", err)
	}

	message := []byte("hello, world!")
	sig, err := key.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != SignatureSize44 {
		t.Errorf("signature size: got %d, want %d", len(sig), SignatureSize44)
	}

	pk := key.PublicKey()
	if !pk.Verify(sig, message, nil) {
		t.Error("Verify returned false for valid signature")
	}

	// Test with modified message
	if pk.Verify(sig, []byte("wrong message"), nil) {
		t.Error("Verify returned true for wrong message")
	}

	// Test with modified signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if pk.Verify(badSig, message, nil) {
		t.Error("Verify returned true for corrupted signature")
	}
}

func TestSignVerify65(t *testing.T) {
	key, err := GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey65 failed: %v", err)
	}

	message := []byte("hello, world!")
	sig, err := key.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != SignatureSize65 {
		t.Errorf("signature size: got %d, want %d", len(sig), SignatureSize65)
	}

	pk := key.PublicKey()
	if !pk.Verify(sig, message, nil) {
		t.Error("Verify returned false for valid signature")
	}

	// Test with modified message
	if pk.Verify(sig, []byte("wrong message"), nil) {
		t.Error("Verify returned true for wrong message")
	}

	// Test with modified signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if pk.Verify(badSig, message, nil) {
		t.Error("Verify returned true for corrupted signature")
	}
}

func TestSignVerify87(t *testing.T) {
	key, err := GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey87 failed: %v", err)
	}

	message := []byte("hello, world!")
	sig, err := key.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != SignatureSize87 {
		t.Errorf("signature size: got %d, want %d", len(sig), SignatureSize87)
	}

	pk := key.PublicKey()
	if !pk.Verify(sig, message, nil) {
		t.Error("Verify returned false for valid signature")
	}

	// Test with modified message
	if pk.Verify(sig, []byte("wrong message"), nil) {
		t.Error("Verify returned true for wrong message")
	}

	// Test with modified signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if pk.Verify(badSig, message, nil) {
		t.Error("Verify returned true for corrupted signature")
	}
}

func TestSignVerifyWithContext65(t *testing.T) {
	key, err := GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey65 failed: %v", err)
	}

	message := []byte("hello, world!")
	context := []byte("test context")

	sig, err := key.Sign(rand.Reader, message, context)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := key.PublicKey()

	// Verify with correct context
	if !pk.Verify(sig, message, context) {
		t.Error("Verify returned false for valid signature with context")
	}

	// Verify with wrong context should fail
	if pk.Verify(sig, message, []byte("wrong context")) {
		t.Error("Verify returned true for wrong context")
	}

	// Verify with no context should fail
	if pk.Verify(sig, message, nil) {
		t.Error("Verify returned true for missing context")
	}
}

func TestKeyRoundtrip44(t *testing.T) {
	key, err := GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey44 failed: %v", err)
	}

	// Test seed roundtrip
	seed := key.Bytes()
	key2, err := NewKey44(seed)
	if err != nil {
		t.Fatalf("NewKey44 failed: %v", err)
	}

	if !bytes.Equal(key.PrivateKeyBytes(), key2.PrivateKeyBytes()) {
		t.Error("key roundtrip via seed failed")
	}

	// Test private key roundtrip
	skBytes := key.PrivateKeyBytes()
	sk, err := NewPrivateKey44(skBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey44 failed: %v", err)
	}
	if !bytes.Equal(sk.Bytes(), skBytes) {
		t.Error("private key roundtrip failed")
	}

	// Test public key roundtrip
	pk := key.PublicKey()
	pkBytes := pk.Bytes()
	pk2, err := NewPublicKey44(pkBytes)
	if err != nil {
		t.Fatalf("NewPublicKey44 failed: %v", err)
	}
	if !bytes.Equal(pk2.Bytes(), pkBytes) {
		t.Error("public key roundtrip failed")
	}
}

func TestKeyRoundtrip65(t *testing.T) {
	key, err := GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey65 failed: %v", err)
	}

	// Test seed roundtrip
	seed := key.Bytes()
	key2, err := NewKey65(seed)
	if err != nil {
		t.Fatalf("NewKey65 failed: %v", err)
	}

	if !bytes.Equal(key.PrivateKeyBytes(), key2.PrivateKeyBytes()) {
		t.Error("key roundtrip via seed failed")
	}

	// Test private key roundtrip
	skBytes := key.PrivateKeyBytes()
	sk, err := NewPrivateKey65(skBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey65 failed: %v", err)
	}
	if !bytes.Equal(sk.Bytes(), skBytes) {
		t.Error("private key roundtrip failed")
	}

	// Test public key roundtrip
	pk := key.PublicKey()
	pkBytes := pk.Bytes()
	pk2, err := NewPublicKey65(pkBytes)
	if err != nil {
		t.Fatalf("NewPublicKey65 failed: %v", err)
	}
	if !bytes.Equal(pk2.Bytes(), pkBytes) {
		t.Error("public key roundtrip failed")
	}
}

func TestKeyRoundtrip87(t *testing.T) {
	key, err := GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey87 failed: %v", err)
	}

	// Test seed roundtrip
	seed := key.Bytes()
	key2, err := NewKey87(seed)
	if err != nil {
		t.Fatalf("NewKey87 failed: %v", err)
	}

	if !bytes.Equal(key.PrivateKeyBytes(), key2.PrivateKeyBytes()) {
		t.Error("key roundtrip via seed failed")
	}

	// Test private key roundtrip
	skBytes := key.PrivateKeyBytes()
	sk, err := NewPrivateKey87(skBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey87 failed: %v", err)
	}
	if !bytes.Equal(sk.Bytes(), skBytes) {
		t.Error("private key roundtrip failed")
	}

	// Test public key roundtrip
	pk := key.PublicKey()
	pkBytes := pk.Bytes()
	pk2, err := NewPublicKey87(pkBytes)
	if err != nil {
		t.Fatalf("NewPublicKey87 failed: %v", err)
	}
	if !bytes.Equal(pk2.Bytes(), pkBytes) {
		t.Error("public key roundtrip failed")
	}
}

func TestKeySizes(t *testing.T) {
	// ML-DSA-44
	key44, _ := GenerateKey44(rand.Reader)
	if len(key44.PublicKey().Bytes()) != PublicKeySize44 {
		t.Errorf("ML-DSA-44 public key size: got %d, want %d",
			len(key44.PublicKey().Bytes()), PublicKeySize44)
	}
	if len(key44.PrivateKeyBytes()) != PrivateKeySize44 {
		t.Errorf("ML-DSA-44 private key size: got %d, want %d",
			len(key44.PrivateKeyBytes()), PrivateKeySize44)
	}

	// ML-DSA-65
	key65, _ := GenerateKey65(rand.Reader)
	if len(key65.PublicKey().Bytes()) != PublicKeySize65 {
		t.Errorf("ML-DSA-65 public key size: got %d, want %d",
			len(key65.PublicKey().Bytes()), PublicKeySize65)
	}
	if len(key65.PrivateKeyBytes()) != PrivateKeySize65 {
		t.Errorf("ML-DSA-65 private key size: got %d, want %d",
			len(key65.PrivateKeyBytes()), PrivateKeySize65)
	}

	// ML-DSA-87
	key87, _ := GenerateKey87(rand.Reader)
	if len(key87.PublicKey().Bytes()) != PublicKeySize87 {
		t.Errorf("ML-DSA-87 public key size: got %d, want %d",
			len(key87.PublicKey().Bytes()), PublicKeySize87)
	}
	if len(key87.PrivateKeyBytes()) != PrivateKeySize87 {
		t.Errorf("ML-DSA-87 private key size: got %d, want %d",
			len(key87.PrivateKeyBytes()), PrivateKeySize87)
	}
}

func TestPublicKeyEquality(t *testing.T) {
	key1, _ := GenerateKey65(rand.Reader)
	key2, _ := GenerateKey65(rand.Reader)

	pk1 := key1.PublicKey()
	pk1Copy := key1.PublicKey()
	pk2 := key2.PublicKey()

	if !pk1.Equal(pk1Copy) {
		t.Error("Equal returned false for same key")
	}
	if pk1.Equal(pk2) {
		t.Error("Equal returned true for different keys")
	}
}

func TestDeterministicKeyGen(t *testing.T) {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	key1, _ := NewKey65(seed)
	key2, _ := NewKey65(seed)

	if !bytes.Equal(key1.PrivateKeyBytes(), key2.PrivateKeyBytes()) {
		t.Error("deterministic key generation produced different keys")
	}
}

func BenchmarkGenerateKey44(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey44(rand.Reader)
	}
}

func BenchmarkGenerateKey65(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey65(rand.Reader)
	}
}

func BenchmarkGenerateKey87(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey87(rand.Reader)
	}
}

func BenchmarkSign44(b *testing.B) {
	key, _ := GenerateKey44(rand.Reader)
	message := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkSign65(b *testing.B) {
	key, _ := GenerateKey65(rand.Reader)
	message := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkSign87(b *testing.B) {
	key, _ := GenerateKey87(rand.Reader)
	message := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkVerify44(b *testing.B) {
	key, _ := GenerateKey44(rand.Reader)
	message := []byte("benchmark message")
	sig, _ := key.Sign(rand.Reader, message, nil)
	pk := key.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, message, nil)
	}
}

func BenchmarkVerify65(b *testing.B) {
	key, _ := GenerateKey65(rand.Reader)
	message := []byte("benchmark message")
	sig, _ := key.Sign(rand.Reader, message, nil)
	pk := key.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, message, nil)
	}
}

func BenchmarkVerify87(b *testing.B) {
	key, _ := GenerateKey87(rand.Reader)
	message := []byte("benchmark message")
	sig, _ := key.Sign(rand.Reader, message, nil)
	pk := key.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, message, nil)
	}
}
