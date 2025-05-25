package didkey

import (
	"github.com/multiformats/go-multicodec"
)

// KeyType represents a cryptographic key type identifier
type KeyType = multicodec.Code

const (
	Ed25519PublicKey    KeyType = multicodec.Ed25519Pub
	X25519PublicKey     KeyType = multicodec.X25519Pub
	Secp256k1PublicKey  KeyType = multicodec.Secp256k1Pub
	Bls12381G1PublicKey KeyType = multicodec.Bls12_381G1Pub
	Bls12381G2PublicKey KeyType = multicodec.Bls12_381G2Pub
	P256PublicKey       KeyType = multicodec.P256Pub
	P384PublicKey       KeyType = multicodec.P384Pub
)

// validateKeySize validates that the key bytes have the correct size for the given key type
func validateKeySize(keyType KeyType, keyBytes []byte) error {
	var expectedSize int

	switch keyType {
	case Ed25519PublicKey:
		expectedSize = 32
	case X25519PublicKey:
		expectedSize = 32
	case Secp256k1PublicKey:
		expectedSize = 33 // Compressed format
	case Bls12381G1PublicKey:
		expectedSize = 48
	case Bls12381G2PublicKey:
		expectedSize = 96
	case P256PublicKey:
		expectedSize = 33 // Compressed format
	case P384PublicKey:
		expectedSize = 49 // Compressed format
	default:
		return ErrUnsupportedKeyTypeWithContext(keyType)
	}

	if len(keyBytes) != expectedSize {
		return ErrInvalidKeySizeWithContext(keyType, expectedSize, len(keyBytes))
	}

	return nil
}
