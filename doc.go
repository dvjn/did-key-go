// Package didkey provides a library for converting between raw cryptographic key bytes
// and DID key format according to the W3C DID Key specification.
//
// The DID Key method is a purely generative method that converts cryptographic public keys
// into decentralized identifiers (DIDs). It supports multiple key types including Ed25519,
// X25519, secp256k1, BLS12-381, P-256, and P-384.
//
// # Format
//
// The DID key format follows this structure:
//
//	did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
//
// Where:
//   - MULTIBASE encodes the data using base58-btc encoding with a 'z' prefix
//   - MULTICODEC prefixes the key bytes with a variable-length integer identifying the key type
//
// # Example Usage
//
//	package main
//
//	import (
//		"fmt"
//		"encoding/hex"
//		"github.com/dvjn/did-key-go"
//	)
//
//	func main() {
//		// Convert raw Ed25519 key bytes to DID key
//		keyHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
//		keyBytes, _ := hex.DecodeString(keyHex)
//
//		didKey, err := didkey.Encode(didkey.KeyTypeEd25519, keyBytes)
//		if err != nil {
//			panic(err)
//		}
//		fmt.Println("DID Key:", didKey)
//		// Output: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
//
//		// Convert DID key back to raw bytes
//		keyType, decodedBytes, err := didkey.Decode(didKey)
//		if err != nil {
//			panic(err)
//		}
//		fmt.Printf("Key Type: %s\n", keyType)
//		fmt.Printf("Key Bytes: %x\n", decodedBytes)
//
//		// Using the DIDKey struct
//		dk, err := didkey.FromBytes(didkey.KeyTypeEd25519, keyBytes)
//		if err != nil {
//			panic(err)
//		}
//
//		didKeyString, _ := dk.String()
//		fmt.Println("DID Key from struct:", didKeyString)
//	}
//
// # Supported Key Types
//
//   - Ed25519: 32-byte signature keys (multicodec: 0xed)
//   - X25519: 32-byte key agreement keys (multicodec: 0xec)
//   - secp256k1: 33-byte compressed public keys (multicodec: 0xe7)
//   - BLS12-381 G1: 48-byte keys (multicodec: 0xea)
//   - BLS12-381 G2: 96-byte keys (multicodec: 0xeb)
//   - P-256: 33-byte compressed public keys (multicodec: 0x1200)
//   - P-384: 49-byte compressed public keys (multicodec: 0x1201)
//
// # Security Considerations
//
// The DID key method is purely generative and does not support key rotation or deactivation.
// It is recommended for short-term interactions and should not be used for long-term identity
// management without appropriate key protection mechanisms.
//
// # Reference
//
// This implementation follows the W3C DID Key specification:
// https://w3c-ccg.github.io/did-key-spec/
package didkey
