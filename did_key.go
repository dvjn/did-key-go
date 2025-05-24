package didkey

import (
	"fmt"
	"strings"
)

const (
	// DIDKeyPrefix is the standard prefix for DID key identifiers
	DIDKeyPrefix = "did:key:"
)

// Encode converts raw key bytes and key type to a DID key string
// Format: did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
func Encode(keyType KeyType, keyBytes []byte) (string, error) {
	if len(keyBytes) == 0 {
		return "", NewError("encode", "key bytes cannot be empty")
	}

	// Validate key size based on type
	if err := validateKeySize(keyType, keyBytes); err != nil {
		return "", err
	}

	// Encode with multicodec prefix
	multicodecBytes, err := encodeMulticodecKey(keyType, keyBytes)
	if err != nil {
		return "", err
	}

	// Encode with multibase
	multibaseString := encodeMultibase(multicodecBytes)

	// Construct DID key
	return DIDKeyPrefix + multibaseString, nil
}

// Decode converts a DID key string back to key type and raw bytes
func Decode(didKey string) (KeyType, []byte, error) {
	// Validate DID key prefix
	if !strings.HasPrefix(didKey, DIDKeyPrefix) {
		return "", nil, NewError("decode", fmt.Sprintf("invalid DID key prefix, expected '%s'", DIDKeyPrefix))
	}

	// Extract multibase part
	multibaseString := didKey[len(DIDKeyPrefix):]
	if multibaseString == "" {
		return "", nil, NewError("decode", "empty multibase string")
	}

	// Decode from multibase
	multicodecBytes, err := decodeMultibase(multibaseString)
	if err != nil {
		return "", nil, NewError("decode", fmt.Sprintf("failed to decode multibase: %v", err))
	}

	// Decode multicodec and extract key
	keyType, keyBytes, err := decodeMulticodecKey(multicodecBytes)
	if err != nil {
		return "", nil, err
	}

	// Validate key size
	if err := validateKeySize(keyType, keyBytes); err != nil {
		return "", nil, err
	}

	return keyType, keyBytes, nil
}

// FromBytes creates a DIDKey from raw bytes and key type
func FromBytes(keyType KeyType, keyBytes []byte) (*DIDKey, error) {
	if err := validateKeySize(keyType, keyBytes); err != nil {
		return nil, err
	}

	return &DIDKey{
		Type: keyType,
		Key:  append([]byte(nil), keyBytes...), // Make a copy
	}, nil
}

// Parse parses a DID key string into a DIDKey struct
func Parse(didKey string) (*DIDKey, error) {
	keyType, keyBytes, err := Decode(didKey)
	if err != nil {
		return nil, err
	}

	return &DIDKey{
		Type: keyType,
		Key:  keyBytes,
	}, nil
}

// String returns the DID key string representation
func (dk *DIDKey) String() (string, error) {
	return Encode(dk.Type, dk.Key)
}

// Bytes returns a copy of the raw key bytes
func (dk *DIDKey) Bytes() []byte {
	return append([]byte(nil), dk.Key...)
}

// validateKeySize validates that the key bytes have the correct size for the given key type
func validateKeySize(keyType KeyType, keyBytes []byte) error {
	var expectedSize int

	switch keyType {
	case KeyTypeEd25519:
		expectedSize = 32
	case KeyTypeX25519:
		expectedSize = 32
	case KeyTypeSecp256k1:
		expectedSize = 33 // Compressed public key
	case KeyTypeBLS12381G1:
		expectedSize = 48
	case KeyTypeBLS12381G2:
		expectedSize = 96
	case KeyTypeP256:
		expectedSize = 33 // Compressed public key
	case KeyTypeP384:
		expectedSize = 49 // Compressed public key
	default:
		return NewError("validate", fmt.Sprintf("unsupported key type: %s", keyType))
	}

	if len(keyBytes) != expectedSize {
		return NewError("validate", fmt.Sprintf("invalid key size for %s: expected %d bytes, got %d", keyType, expectedSize, len(keyBytes)))
	}

	return nil
}

// IsValidDIDKey checks if a string is a valid DID key format
func IsValidDIDKey(didKey string) bool {
	_, _, err := Decode(didKey)
	return err == nil
}

// GetKeyType extracts just the key type from a DID key string without full validation
func GetKeyType(didKey string) (KeyType, error) {
	keyType, _, err := Decode(didKey)
	return keyType, err
}
