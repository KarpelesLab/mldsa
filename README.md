# mldsa

A pure Go implementation of ML-DSA (Module-Lattice Digital Signature Algorithm) as specified in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

ML-DSA is a post-quantum digital signature scheme standardized by NIST, designed to be secure against attacks by quantum computers.

## Features

- Pure Go implementation with no external dependencies (only standard library)
- Supports all three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87
- Implements `crypto.Signer` and `crypto.MessageSigner` (Go 1.25+) interfaces
- Simple, clean API
- FIPS 204 compliant (validated against NIST ACVP test vectors)
- MIT licensed

## Installation

```bash
go get github.com/KarpelesLab/mldsa
```

## Security Levels

| Parameter Set | Security Level | Public Key | Private Key | Signature |
|--------------|----------------|------------|-------------|-----------|
| ML-DSA-44    | 128-bit        | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65    | 192-bit        | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87    | 256-bit        | 2,592 bytes | 4,896 bytes | 4,627 bytes |

## Usage

### Key Generation

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/KarpelesLab/mldsa"
)

func main() {
    // Generate a new ML-DSA-65 key pair
    key, err := mldsa.GenerateKey65(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // Get the public key
    publicKey := key.PublicKey()

    fmt.Printf("Public key size: %d bytes\n", len(publicKey.Bytes()))
}
```

### Signing and Verification

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/KarpelesLab/mldsa"
)

func main() {
    // Generate key pair
    key, err := mldsa.GenerateKey65(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    message := []byte("Hello, post-quantum world!")

    // Sign the message using crypto.Signer interface
    signature, err := key.Sign(rand.Reader, message, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signature size: %d bytes\n", len(signature))

    // Verify the signature
    publicKey := key.PublicKey()
    valid := publicKey.Verify(signature, message, nil)
    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Using Context Strings

ML-DSA supports optional context strings (up to 255 bytes) for domain separation:

```go
context := []byte("my-application-v1")

// Sign with context using SignWithContext
signature, err := key.SignWithContext(rand.Reader, message, context)
if err != nil {
    log.Fatal(err)
}

// Or use SignerOpts with the crypto.Signer interface
opts := &mldsa.SignerOpts{Context: context}
signature, err = key.Sign(rand.Reader, message, opts)
if err != nil {
    log.Fatal(err)
}

// Verify with the same context
valid := publicKey.Verify(signature, message, context)
```

### Key Serialization

```go
// Serialize keys
seed := key.Bytes()              // 32-byte seed (can regenerate full key)
privateKeyBytes := key.PrivateKeyBytes()  // Full private key
publicKeyBytes := publicKey.Bytes()       // Public key

// Deserialize keys
key2, err := mldsa.NewKey65(seed)
if err != nil {
    log.Fatal(err)
}

privateKey, err := mldsa.NewPrivateKey65(privateKeyBytes)
if err != nil {
    log.Fatal(err)
}

publicKey2, err := mldsa.NewPublicKey65(publicKeyBytes)
if err != nil {
    log.Fatal(err)
}
```

## API Reference

### Key Generation Functions

```go
// ML-DSA-44 (128-bit security)
func GenerateKey44(rand io.Reader) (*Key44, error)
func NewKey44(seed []byte) (*Key44, error)
func NewPrivateKey44(b []byte) (*PrivateKey44, error)
func NewPublicKey44(b []byte) (*PublicKey44, error)

// ML-DSA-65 (192-bit security)
func GenerateKey65(rand io.Reader) (*Key65, error)
func NewKey65(seed []byte) (*Key65, error)
func NewPrivateKey65(b []byte) (*PrivateKey65, error)
func NewPublicKey65(b []byte) (*PublicKey65, error)

// ML-DSA-87 (256-bit security)
func GenerateKey87(rand io.Reader) (*Key87, error)
func NewKey87(seed []byte) (*Key87, error)
func NewPrivateKey87(b []byte) (*PrivateKey87, error)
func NewPublicKey87(b []byte) (*PublicKey87, error)
```

### Key Types

Each security level has three key types:

- `Key*` - A full key pair (contains both private and public key, plus the original seed)
- `PrivateKey*` - A standalone private key (can sign messages)
- `PublicKey*` - A standalone public key (can verify signatures)

### Key Methods

```go
// Key pair methods
func (key *Key65) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (key *Key65) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error)
func (key *Key65) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error)
func (key *Key65) PublicKey() *PublicKey65
func (key *Key65) Bytes() []byte           // Returns 32-byte seed
func (key *Key65) PrivateKeyBytes() []byte // Returns full private key

// Private key methods (implements crypto.Signer and crypto.MessageSigner)
func (sk *PrivateKey65) Public() crypto.PublicKey
func (sk *PrivateKey65) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (sk *PrivateKey65) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error)
func (sk *PrivateKey65) SignWithContext(rand io.Reader, message, context []byte) ([]byte, error)
func (sk *PrivateKey65) Bytes() []byte

// Public key methods
func (pk *PublicKey65) Verify(sig, message, context []byte) bool
func (pk *PublicKey65) Bytes() []byte
func (pk *PublicKey65) Equal(other crypto.PublicKey) bool
```

### SignerOpts

```go
// SignerOpts implements crypto.SignerOpts for ML-DSA signing operations.
type SignerOpts struct {
    Context []byte // Optional context string (max 255 bytes)
}

func (opts *SignerOpts) HashFunc() crypto.Hash // Returns 0 (ML-DSA signs messages directly)
```

## Constants

```go
const (
    SeedSize = 32  // Size of the seed for key generation

    // ML-DSA-44
    PublicKeySize44  = 1312
    PrivateKeySize44 = 2560
    SignatureSize44  = 2420

    // ML-DSA-65
    PublicKeySize65  = 1952
    PrivateKeySize65 = 4032
    SignatureSize65  = 3309

    // ML-DSA-87
    PublicKeySize87  = 2592
    PrivateKeySize87 = 4896
    SignatureSize87  = 4627
)
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
