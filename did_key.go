package didkey

import (
	"strings"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

const (
	DIDKeyPrefix = "did:key:"
)

// Encode converts raw key bytes and key type to a DID key string
// Format: did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
func Encode(keyType KeyType, keyBytes []byte) (string, error) {
	if len(keyBytes) == 0 {
		return "", ErrEmptyKeyBytes
	}

	if err := validateKeySize(keyType, keyBytes); err != nil {
		return "", err
	}

	codecBytes := varint.ToUvarint(uint64(keyType))
	multicodecBytes := make([]byte, len(codecBytes)+len(keyBytes))
	copy(multicodecBytes, codecBytes)
	copy(multicodecBytes[len(codecBytes):], keyBytes)

	multibaseString, err := multibase.Encode(multibase.Base58BTC, multicodecBytes)
	if err != nil {
		return "", ErrMultibaseEncodeFailedWithContext(err)
	}

	return DIDKeyPrefix + multibaseString, nil
}

// Decode converts a DID key string back to key type and raw bytes
func Decode(didKey string) (KeyType, []byte, error) {
	if !strings.HasPrefix(didKey, DIDKeyPrefix) {
		return 0, nil, ErrInvalidDIDKeyPrefixWithContext(DIDKeyPrefix)
	}

	multibaseString := didKey[len(DIDKeyPrefix):]
	if multibaseString == "" {
		return 0, nil, ErrEmptyMultibaseString
	}

	encoding, multicodecBytes, err := multibase.Decode(multibaseString)
	if err != nil {
		return 0, nil, ErrMultibaseDecodeFailedWithContext(err)
	}

	// DID keys must use base58-btc encoding per specification
	if encoding != multibase.Base58BTC {
		return 0, nil, ErrExpectedBase58BTC
	}

	if len(multicodecBytes) == 0 {
		return 0, nil, ErrEmptyData
	}

	value, bytesRead, err := varint.FromUvarint(multicodecBytes)
	if err != nil {
		return 0, nil, ErrInvalidVarintWithContext(err)
	}

	if bytesRead >= len(multicodecBytes) {
		return 0, nil, ErrNoKeyDataAfterVarint
	}

	keyType := KeyType(value)
	keyBytes := multicodecBytes[bytesRead:]

	if err := validateKeySize(keyType, keyBytes); err != nil {
		return 0, nil, err
	}

	return keyType, keyBytes, nil
}
