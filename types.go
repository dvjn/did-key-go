package didkey

import "fmt"

// KeyType represents the type of cryptographic key
type KeyType string

const (
	// KeyTypeEd25519 represents Ed25519 signature keys
	KeyTypeEd25519 KeyType = "Ed25519"

	// KeyTypeX25519 represents X25519 key agreement keys
	KeyTypeX25519 KeyType = "X25519"

	// KeyTypeSecp256k1 represents secp256k1 keys
	KeyTypeSecp256k1 KeyType = "secp256k1"

	// KeyTypeBLS12381G1 represents BLS12-381 G1 keys
	KeyTypeBLS12381G1 KeyType = "BLS12381G1"

	// KeyTypeBLS12381G2 represents BLS12-381 G2 keys
	KeyTypeBLS12381G2 KeyType = "BLS12381G2"

	// KeyTypeP256 represents P-256 (secp256r1) keys
	KeyTypeP256 KeyType = "P-256"

	// KeyTypeP384 represents P-384 (secp384r1) keys
	KeyTypeP384 KeyType = "P-384"
)

// Multicodec constants for different key types
// These are used to prefix the key bytes when encoding to multibase
const (
	// Ed25519 public key multicodec
	MulticodecEd25519Pub = 0xed

	// X25519 public key multicodec
	MulticodecX25519Pub = 0xec

	// secp256k1 public key multicodec
	MulticodecSecp256k1Pub = 0xe7

	// BLS12-381 G1 public key multicodec
	MulticodecBLS12381G1Pub = 0xea

	// BLS12-381 G2 public key multicodec
	MulticodecBLS12381G2Pub = 0xeb

	// P-256 public key multicodec
	MulticodecP256Pub = 0x1200

	// P-384 public key multicodec
	MulticodecP384Pub = 0x1201
)

// DIDKey represents a DID key with its type and raw bytes
type DIDKey struct {
	Type KeyType
	Key  []byte
}

// Error represents errors that can occur during DID key operations
type Error struct {
	Operation string
	Reason    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("did:key %s: %s", e.Operation, e.Reason)
}

// NewError creates a new DID key error
func NewError(operation, reason string) *Error {
	return &Error{
		Operation: operation,
		Reason:    reason,
	}
}
