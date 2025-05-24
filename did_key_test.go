package didkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors using real DID keys and their corresponding raw bytes
var testVectors = map[string]struct {
	keyType   KeyType
	keyHex    string
	didKey    string
	shouldErr bool
}{
	"Ed25519-from-spec": {
		keyType: KeyTypeEd25519,
		keyHex:  "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6",
		didKey:  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
	},
	"Ed25519-test-1": {
		keyType: KeyTypeEd25519,
		keyHex:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		didKey:  "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
	},
	"Ed25519-test-2": {
		keyType: KeyTypeEd25519,
		keyHex:  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		didKey:  "did:key:z6MkfgKfvJf5pnfqLkJt7K2nhoK9k35dd3V8q7AFhJFm4PCa",
	},
	"Secp256k1-test": {
		keyType: KeyTypeSecp256k1,
		keyHex:  "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479",
		didKey:  "did:key:zQ3shwiy5TJU1fJ7XH6eJLRXJYvh6tuU4YKZmfU46JtJtHTAx",
	},
	"P-256-test": {
		keyType: KeyTypeP256,
		keyHex:  "02d0ef6c6209e4e3d0de5e555b9b3f7e3c5a4c7b1e9e2d8c3f4a5b6c7d8e9f01a0",
		didKey:  "did:key:zDnaeeVZbSMKojCG3A1k46yRNVhLV7XXxr2mniUF13p3FSyXm",
	},
}

func TestEncode(t *testing.T) {
	for name, tv := range testVectors {
		t.Run(name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tv.keyHex)
			if err != nil {
				t.Fatalf("Failed to decode test hex: %v", err)
			}

			result, err := Encode(tv.keyType, keyBytes)
			if tv.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result != tv.didKey {
				t.Errorf("Expected %s, got %s", tv.didKey, result)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	for name, tv := range testVectors {
		t.Run(name, func(t *testing.T) {
			expectedKeyBytes, err := hex.DecodeString(tv.keyHex)
			if err != nil {
				t.Fatalf("Failed to decode test hex: %v", err)
			}

			keyType, keyBytes, err := Decode(tv.didKey)
			if tv.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if keyType != tv.keyType {
				t.Errorf("Expected key type %s, got %s", tv.keyType, keyType)
			}

			if !bytes.Equal(keyBytes, expectedKeyBytes) {
				t.Errorf("Expected key bytes %x, got %x", expectedKeyBytes, keyBytes)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	for name, tv := range testVectors {
		t.Run(name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tv.keyHex)
			if err != nil {
				t.Fatalf("Failed to decode test hex: %v", err)
			}

			// Encode
			didKey, err := Encode(tv.keyType, keyBytes)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			// Decode
			decodedKeyType, decodedKeyBytes, err := Decode(didKey)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			// Verify
			if decodedKeyType != tv.keyType {
				t.Errorf("Key type mismatch: expected %s, got %s", tv.keyType, decodedKeyType)
			}

			if !bytes.Equal(decodedKeyBytes, keyBytes) {
				t.Errorf("Key bytes mismatch: expected %x, got %x", keyBytes, decodedKeyBytes)
			}
		})
	}
}

func TestDIDKeyStruct(t *testing.T) {
	keyBytes, _ := hex.DecodeString("2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6")

	didKey, err := FromBytes(KeyTypeEd25519, keyBytes)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	// Test String method
	didKeyString, err := didKey.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	expected := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if didKeyString != expected {
		t.Errorf("Expected %s, got %s", expected, didKeyString)
	}

	// Test Bytes method
	retrievedBytes := didKey.Bytes()
	if !bytes.Equal(retrievedBytes, keyBytes) {
		t.Errorf("Bytes mismatch: expected %x, got %x", keyBytes, retrievedBytes)
	}

	// Test Parse
	parsedDIDKey, err := Parse(didKeyString)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsedDIDKey.Type != KeyTypeEd25519 {
		t.Errorf("Parsed key type mismatch: expected %s, got %s", KeyTypeEd25519, parsedDIDKey.Type)
	}

	if !bytes.Equal(parsedDIDKey.Key, keyBytes) {
		t.Errorf("Parsed key bytes mismatch: expected %x, got %x", keyBytes, parsedDIDKey.Key)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		keyBytes  []byte
		shouldErr bool
	}{
		{
			name:      "Valid Ed25519",
			keyType:   KeyTypeEd25519,
			keyBytes:  make([]byte, 32),
			shouldErr: false,
		},
		{
			name:      "Invalid Ed25519 size",
			keyType:   KeyTypeEd25519,
			keyBytes:  make([]byte, 31),
			shouldErr: true,
		},
		{
			name:      "Empty bytes",
			keyType:   KeyTypeEd25519,
			keyBytes:  []byte{},
			shouldErr: true,
		},
		{
			name:      "Valid Secp256k1",
			keyType:   KeyTypeSecp256k1,
			keyBytes:  make([]byte, 33),
			shouldErr: false,
		},
		{
			name:      "Invalid Secp256k1 size",
			keyType:   KeyTypeSecp256k1,
			keyBytes:  make([]byte, 32),
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encode(tt.keyType, tt.keyBytes)
			if tt.shouldErr && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestIsValidDIDKey(t *testing.T) {
	tests := []struct {
		name    string
		didKey  string
		isValid bool
	}{
		{
			name:    "Valid Ed25519 DID key",
			didKey:  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			isValid: true,
		},
		{
			name:    "Invalid prefix",
			didKey:  "did:web:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			isValid: false,
		},
		{
			name:    "Invalid format",
			didKey:  "not-a-did-key",
			isValid: false,
		},
		{
			name:    "Empty string",
			didKey:  "",
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := IsValidDIDKey(tt.didKey)
			if isValid != tt.isValid {
				t.Errorf("Expected %v, got %v", tt.isValid, isValid)
			}
		})
	}
}

func TestGetKeyType(t *testing.T) {
	keyType, err := GetKeyType("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if keyType != KeyTypeEd25519 {
		t.Errorf("Expected %s, got %s", KeyTypeEd25519, keyType)
	}
}

func TestErrorHandling(t *testing.T) {
	// Test invalid DID key prefix
	_, _, err := Decode("did:web:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	if err == nil {
		t.Errorf("Expected error for invalid prefix")
	}

	// Test invalid multibase
	_, _, err = Decode("did:key:invalid-multibase")
	if err == nil {
		t.Errorf("Expected error for invalid multibase")
	}

	// Test empty key bytes
	_, err = Encode(KeyTypeEd25519, []byte{})
	if err == nil {
		t.Errorf("Expected error for empty key bytes")
	}
}

// Test the specific examples from the W3C specification
func TestSpecificationExamples(t *testing.T) {
	// Test the main example from the spec
	specDID := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	keyType, keyBytes, err := Decode(specDID)
	if err != nil {
		t.Fatalf("Failed to decode spec DID: %v", err)
	}

	if keyType != KeyTypeEd25519 {
		t.Errorf("Expected Ed25519, got %s", keyType)
	}

	if len(keyBytes) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(keyBytes))
	}

	// Test round-trip
	reencoded, err := Encode(keyType, keyBytes)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if reencoded != specDID {
		t.Errorf("Round-trip failed: expected %s, got %s", specDID, reencoded)
	}
}
