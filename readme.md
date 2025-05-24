# DID Key Library

A Go library for converting between raw cryptographic key bytes and [DID Key](https://w3c-ccg.github.io/did-key-spec/) format according to the W3C specification.

## Overview

The DID Key method is a purely generative method that converts cryptographic public keys into decentralized identifiers (DIDs). This library provides functionality to:

- Convert raw key bytes to DID key format
- Parse DID keys back to raw bytes and key type
- Support multiple cryptographic key types
- Validate DID key format and key sizes

## Format

DID keys follow this structure:
```
did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
```

Where:
- **MULTIBASE**: Encodes data using base58-btc with 'z' prefix
- **MULTICODEC**: Prefixes key bytes with variable-length integer identifying key type

## Supported Key Types

| Key Type     | Size     | Multicodec | DID Prefix | Example                                                                                                                                           |
| ------------ | -------- | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ed25519      | 32 bytes | 0xed       | `z6Mk`     | `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`                                                                                        |
| X25519       | 32 bytes | 0xec       | `z6LS`     | `did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p`                                                                                        |
| secp256k1    | 33 bytes | 0xe7       | `zQ3s`     | `did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme`                                                                                       |
| BLS12-381 G1 | 48 bytes | 0xea       | `zUC7`     | `did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY` |
| BLS12-381 G2 | 96 bytes | 0xeb       | `zUC7`     | -                                                                                                                                                 |
| P-256        | 33 bytes | 0x1200     | `zDn`      | `did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169`                                                                                       |
| P-384        | 49 bytes | 0x1201     | `z82`      | `did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9`                                                                 |

## Installation

```bash
go get github.com/dvjn/did-key-go
```

## Usage

### Basic Encoding/Decoding

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/dvjn/did-key-go"
)

func main() {
    // Example Ed25519 public key
    keyHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    keyBytes, _ := hex.DecodeString(keyHex)

    // Encode to DID key
    didKey, err := didkey.Encode(didkey.KeyTypeEd25519, keyBytes)
    if err != nil {
        panic(err)
    }
    fmt.Println("DID Key:", didKey)
    // Output: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

    // Decode back to raw bytes
    keyType, decodedBytes, err := didkey.Decode(didKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Key Type: %s\n", keyType)
    fmt.Printf("Key Bytes: %x\n", decodedBytes)
}
```

### Using the DIDKey Struct

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/dvjn/did-key-go"
)

func main() {
    keyBytes, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    // Create DIDKey from bytes
    dk, err := didkey.FromBytes(didkey.KeyTypeEd25519, keyBytes)
    if err != nil {
        panic(err)
    }

    // Get DID key string
    didKeyString, _ := dk.String()
    fmt.Println("DID Key:", didKeyString)

    // Get raw bytes (returns a copy)
    originalBytes := dk.Bytes()
    fmt.Printf("Key Bytes: %x\n", originalBytes)

    // Parse from DID key string
    parsedDK, err := didkey.Parse(didKeyString)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Parsed Key Type: %s\n", parsedDK.Type)
}
```

### Validation and Utility Functions

```go
package main

import (
    "fmt"
    "github.com/dvjn/did-key-go"
)

func main() {
    didKey := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    // Check if valid DID key
    if didkey.IsValidDIDKey(didKey) {
        fmt.Println("Valid DID key")
    }

    // Extract key type only
    keyType, err := didkey.GetKeyType(didKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Key Type: %s\n", keyType)
}
```

### Working with Different Key Types

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/dvjn/did-key-go"
)

func main() {
    // secp256k1 example (33 bytes compressed)
    secp256k1Key, _ := hex.DecodeString("03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479")
    secp256k1DID, _ := didkey.Encode(didkey.KeyTypeSecp256k1, secp256k1Key)
    fmt.Println("secp256k1 DID:", secp256k1DID)

    // P-256 example (33 bytes compressed)
    p256Key, _ := hex.DecodeString("03d0ef6c6209e4e3d0de5e555b9b3f7e3c5a4c7b1e9e2d8c3f4a5b6c7d8e9f0a1")
    p256DID, _ := didkey.Encode(didkey.KeyTypeP256, p256Key)
    fmt.Println("P-256 DID:", p256DID)

    // X25519 example (32 bytes)
    x25519Key := make([]byte, 32) // Example key
    x25519DID, _ := didkey.Encode(didkey.KeyTypeX25519, x25519Key)
    fmt.Println("X25519 DID:", x25519DID)
}
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **No Key Rotation**: DID keys are purely generative and cannot be updated or rotated
2. **No Deactivation**: Compromised keys cannot be deactivated
3. **Short-term Use**: Recommended only for short-term interactions
4. **Key Protection**: Ensure proper key storage and protection mechanisms


## License

This project is licensed under the MIT License.

## References

- [W3C DID Key Specification](https://w3c-ccg.github.io/did-key-spec/)
- [Multibase Specification](https://github.com/multiformats/multibase)
 