package mldsa

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// hexBytes is a helper type for JSON unmarshaling of hex strings
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestACVPKeyGen(t *testing.T) {
	testACVPKeyGen(t, "ML-DSA-44", NewKey44, PublicKeySize44, PrivateKeySize44)
	testACVPKeyGen(t, "ML-DSA-65", NewKey65, PublicKeySize65, PrivateKeySize65)
	testACVPKeyGen(t, "ML-DSA-87", NewKey87, PublicKeySize87, PrivateKeySize87)
}

type keyGenFunc interface {
	PublicKeyBytes() []byte
	PrivateKeyBytes() []byte
}

func testACVPKeyGen[K keyGenFunc](t *testing.T, paramSet string, newKey func([]byte) (K, error), pkSize, skSize int) {
	t.Run(paramSet, func(t *testing.T) {
		promptData, err := readGzip("testdata/ML-DSA-keyGen-FIPS204/prompt.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		resultsData, err := readGzip("testdata/ML-DSA-keyGen-FIPS204/expectedResults.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		var prompt struct {
			TestGroups []struct {
				TgID         int    `json:"tgId"`
				ParameterSet string `json:"parameterSet"`
				Tests        []struct {
					TcID int      `json:"tcId"`
					Seed hexBytes `json:"seed"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(promptData, &prompt); err != nil {
			t.Fatal(err)
		}

		var results struct {
			TestGroups []struct {
				TgID  int `json:"tgId"`
				Tests []struct {
					TcID int      `json:"tcId"`
					Pk   hexBytes `json:"pk"`
					Sk   hexBytes `json:"sk"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(resultsData, &results); err != nil {
			t.Fatal(err)
		}

		// Build lookup map for results
		type resultKey struct {
			tgID, tcID int
		}
		resultMap := make(map[resultKey]struct {
			pk, sk hexBytes
		})
		for _, group := range results.TestGroups {
			for _, test := range group.Tests {
				resultMap[resultKey{group.TgID, test.TcID}] = struct{ pk, sk hexBytes }{test.Pk, test.Sk}
			}
		}

		for _, group := range prompt.TestGroups {
			if group.ParameterSet != paramSet {
				continue
			}

			for _, test := range group.Tests {
				result, ok := resultMap[resultKey{group.TgID, test.TcID}]
				if !ok {
					t.Fatalf("Missing result for tgId=%d, tcId=%d", group.TgID, test.TcID)
				}

				key, err := newKey(test.Seed)
				if err != nil {
					t.Fatalf("tcId=%d: NewKey failed: %v", test.TcID, err)
				}

				// Get the key pair interface to access both keys
				pk := key.PublicKeyBytes()
				sk := key.PrivateKeyBytes()

				if !bytes.Equal(pk, result.pk) {
					t.Errorf("tcId=%d: public key mismatch\ngot:  %x\nwant: %x", test.TcID, pk, result.pk)
				}
				if !bytes.Equal(sk, result.sk) {
					t.Errorf("tcId=%d: private key mismatch\ngot:  %x\nwant: %x", test.TcID, sk, result.sk)
				}
			}
		}
	})
}

// Helper interfaces to get the public key bytes from Key types
func (k *Key44) PublicKeyBytes() []byte { return k.PublicKey().Bytes() }
func (k *Key65) PublicKeyBytes() []byte { return k.PublicKey().Bytes() }
func (k *Key87) PublicKeyBytes() []byte { return k.PublicKey().Bytes() }

func TestACVPSigVer(t *testing.T) {
	testACVPSigVer(t, "ML-DSA-44", NewPublicKey44, PublicKeySize44, SignatureSize44)
	testACVPSigVer(t, "ML-DSA-65", NewPublicKey65, PublicKeySize65, SignatureSize65)
	testACVPSigVer(t, "ML-DSA-87", NewPublicKey87, PublicKeySize87, SignatureSize87)
}

type verifier interface {
	verifyInternal(sig, mu []byte) bool
}

func testACVPSigVer[PK verifier](t *testing.T, paramSet string, newPK func([]byte) (PK, error), pkSize, sigSize int) {
	t.Run(paramSet, func(t *testing.T) {
		promptData, err := readGzip("testdata/ML-DSA-sigVer-FIPS204/prompt.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		resultsData, err := readGzip("testdata/ML-DSA-sigVer-FIPS204/expectedResults.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		var prompt struct {
			TestGroups []struct {
				TgID         int      `json:"tgId"`
				ParameterSet string   `json:"parameterSet"`
				Pk           hexBytes `json:"pk"`
				Tests        []struct {
					TcID      int      `json:"tcId"`
					Message   hexBytes `json:"message"`
					Signature hexBytes `json:"signature"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(promptData, &prompt); err != nil {
			t.Fatal(err)
		}

		var results struct {
			TestGroups []struct {
				TgID  int `json:"tgId"`
				Tests []struct {
					TcID       int  `json:"tcId"`
					TestPassed bool `json:"testPassed"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(resultsData, &results); err != nil {
			t.Fatal(err)
		}

		// Build lookup map for results
		type resultKey struct {
			tgID, tcID int
		}
		resultMap := make(map[resultKey]bool)
		for _, group := range results.TestGroups {
			for _, test := range group.Tests {
				resultMap[resultKey{group.TgID, test.TcID}] = test.TestPassed
			}
		}

		for _, group := range prompt.TestGroups {
			if group.ParameterSet != paramSet {
				continue
			}

			pk, err := newPK(group.Pk)
			if err != nil {
				t.Fatalf("tgId=%d: NewPublicKey failed: %v", group.TgID, err)
			}

			for _, test := range group.Tests {
				expected, ok := resultMap[resultKey{group.TgID, test.TcID}]
				if !ok {
					t.Fatalf("Missing result for tgId=%d, tcId=%d", group.TgID, test.TcID)
				}

				// The ACVP tests use the internal verify which takes mu directly
				// mu is the message for internal verification
				got := pk.verifyInternal(test.Signature, test.Message)

				if got != expected {
					t.Errorf("tcId=%d: verification result mismatch: got %v, want %v", test.TcID, got, expected)
				}
			}
		}
	})
}

func TestACVPSigGen(t *testing.T) {
	testACVPSigGen44(t)
	testACVPSigGen65(t)
	testACVPSigGen87(t)
}

func testACVPSigGen44(t *testing.T) {
	t.Run("ML-DSA-44", func(t *testing.T) {
		promptData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/prompt.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		resultsData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/expectedResults.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		var prompt struct {
			TestGroups []struct {
				TgID          int    `json:"tgId"`
				ParameterSet  string `json:"parameterSet"`
				Deterministic bool   `json:"deterministic"`
				Tests         []struct {
					TcID    int      `json:"tcId"`
					Sk      hexBytes `json:"sk"`
					Message hexBytes `json:"message"`
					Rnd     hexBytes `json:"rnd"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(promptData, &prompt); err != nil {
			t.Fatal(err)
		}

		var results struct {
			TestGroups []struct {
				TgID  int `json:"tgId"`
				Tests []struct {
					TcID      int      `json:"tcId"`
					Signature hexBytes `json:"signature"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(resultsData, &results); err != nil {
			t.Fatal(err)
		}

		// Build lookup map for results
		type resultKey struct {
			tgID, tcID int
		}
		resultMap := make(map[resultKey]hexBytes)
		for _, group := range results.TestGroups {
			for _, test := range group.Tests {
				resultMap[resultKey{group.TgID, test.TcID}] = test.Signature
			}
		}

		for _, group := range prompt.TestGroups {
			if group.ParameterSet != "ML-DSA-44" {
				continue
			}

			for _, test := range group.Tests {
				expected, ok := resultMap[resultKey{group.TgID, test.TcID}]
				if !ok {
					t.Fatalf("Missing result for tgId=%d, tcId=%d", group.TgID, test.TcID)
				}

				sk, err := NewPrivateKey44(test.Sk)
				if err != nil {
					t.Fatalf("tcId=%d: NewPrivateKey failed: %v", test.TcID, err)
				}

				var rnd [32]byte
				if !group.Deterministic {
					copy(rnd[:], test.Rnd)
				}

				// Sign internally with the provided randomness
				sig, err := sk.signInternal(rnd[:], test.Message)
				if err != nil {
					t.Fatalf("tcId=%d: signInternal failed: %v", test.TcID, err)
				}

				if !bytes.Equal(sig, expected) {
					t.Errorf("tcId=%d: signature mismatch\ngot:  %x\nwant: %x", test.TcID, sig, expected)
				}
			}
		}
	})
}

func testACVPSigGen65(t *testing.T) {
	t.Run("ML-DSA-65", func(t *testing.T) {
		promptData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/prompt.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		resultsData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/expectedResults.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		var prompt struct {
			TestGroups []struct {
				TgID          int    `json:"tgId"`
				ParameterSet  string `json:"parameterSet"`
				Deterministic bool   `json:"deterministic"`
				Tests         []struct {
					TcID    int      `json:"tcId"`
					Sk      hexBytes `json:"sk"`
					Message hexBytes `json:"message"`
					Rnd     hexBytes `json:"rnd"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(promptData, &prompt); err != nil {
			t.Fatal(err)
		}

		var results struct {
			TestGroups []struct {
				TgID  int `json:"tgId"`
				Tests []struct {
					TcID      int      `json:"tcId"`
					Signature hexBytes `json:"signature"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(resultsData, &results); err != nil {
			t.Fatal(err)
		}

		type resultKey struct {
			tgID, tcID int
		}
		resultMap := make(map[resultKey]hexBytes)
		for _, group := range results.TestGroups {
			for _, test := range group.Tests {
				resultMap[resultKey{group.TgID, test.TcID}] = test.Signature
			}
		}

		for _, group := range prompt.TestGroups {
			if group.ParameterSet != "ML-DSA-65" {
				continue
			}

			for _, test := range group.Tests {
				expected, ok := resultMap[resultKey{group.TgID, test.TcID}]
				if !ok {
					t.Fatalf("Missing result for tgId=%d, tcId=%d", group.TgID, test.TcID)
				}

				sk, err := NewPrivateKey65(test.Sk)
				if err != nil {
					t.Fatalf("tcId=%d: NewPrivateKey failed: %v", test.TcID, err)
				}

				var rnd [32]byte
				if !group.Deterministic {
					copy(rnd[:], test.Rnd)
				}

				sig, err := sk.signInternal(rnd[:], test.Message)
				if err != nil {
					t.Fatalf("tcId=%d: signInternal failed: %v", test.TcID, err)
				}

				if !bytes.Equal(sig, expected) {
					t.Errorf("tcId=%d: signature mismatch\ngot:  %x\nwant: %x", test.TcID, sig, expected)
				}
			}
		}
	})
}

func testACVPSigGen87(t *testing.T) {
	t.Run("ML-DSA-87", func(t *testing.T) {
		promptData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/prompt.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		resultsData, err := readGzip("testdata/ML-DSA-sigGen-FIPS204/expectedResults.json.gz")
		if err != nil {
			t.Skipf("Could not read test data: %v", err)
		}

		var prompt struct {
			TestGroups []struct {
				TgID          int    `json:"tgId"`
				ParameterSet  string `json:"parameterSet"`
				Deterministic bool   `json:"deterministic"`
				Tests         []struct {
					TcID    int      `json:"tcId"`
					Sk      hexBytes `json:"sk"`
					Message hexBytes `json:"message"`
					Rnd     hexBytes `json:"rnd"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(promptData, &prompt); err != nil {
			t.Fatal(err)
		}

		var results struct {
			TestGroups []struct {
				TgID  int `json:"tgId"`
				Tests []struct {
					TcID      int      `json:"tcId"`
					Signature hexBytes `json:"signature"`
				} `json:"tests"`
			} `json:"testGroups"`
		}
		if err := json.Unmarshal(resultsData, &results); err != nil {
			t.Fatal(err)
		}

		type resultKey struct {
			tgID, tcID int
		}
		resultMap := make(map[resultKey]hexBytes)
		for _, group := range results.TestGroups {
			for _, test := range group.Tests {
				resultMap[resultKey{group.TgID, test.TcID}] = test.Signature
			}
		}

		for _, group := range prompt.TestGroups {
			if group.ParameterSet != "ML-DSA-87" {
				continue
			}

			for _, test := range group.Tests {
				expected, ok := resultMap[resultKey{group.TgID, test.TcID}]
				if !ok {
					t.Fatalf("Missing result for tgId=%d, tcId=%d", group.TgID, test.TcID)
				}

				sk, err := NewPrivateKey87(test.Sk)
				if err != nil {
					t.Fatalf("tcId=%d: NewPrivateKey failed: %v", test.TcID, err)
				}

				var rnd [32]byte
				if !group.Deterministic {
					copy(rnd[:], test.Rnd)
				}

				sig, err := sk.signInternal(rnd[:], test.Message)
				if err != nil {
					t.Fatalf("tcId=%d: signInternal failed: %v", test.TcID, err)
				}

				if !bytes.Equal(sig, expected) {
					t.Errorf("tcId=%d: signature mismatch\ngot:  %x\nwant: %x", test.TcID, sig, expected)
				}
			}
		}
	})
}
