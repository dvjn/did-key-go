package didkey

import (
	"errors"
	"fmt"
)

var (
	// Encoding errors
	ErrEmptyKeyBytes         = errors.New("key bytes cannot be empty")
	ErrMultibaseEncodeFailed = errors.New("failed to encode multibase")

	// Decoding errors
	ErrEmptyMultibaseString  = errors.New("empty multibase string")
	ErrInvalidDIDKeyPrefix   = errors.New("invalid DID key prefix")
	ErrExpectedBase58BTC     = errors.New("expected base58-btc encoding")
	ErrEmptyData             = errors.New("empty data")
	ErrInvalidVarint         = errors.New("invalid varint")
	ErrNoKeyDataAfterVarint  = errors.New("no key data after varint")
	ErrMultibaseDecodeFailed = errors.New("failed to decode multibase")

	// Validation errors (used by both encoding and decoding)
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	ErrInvalidKeySize     = errors.New("invalid key size")
)

func ErrInvalidDIDKeyPrefixWithContext(expected string) error {
	return fmt.Errorf("%w, expected '%s'", ErrInvalidDIDKeyPrefix, expected)
}

func ErrMultibaseEncodeFailedWithContext(err error) error {
	return fmt.Errorf("%w: %w", ErrMultibaseEncodeFailed, err)
}

func ErrMultibaseDecodeFailedWithContext(err error) error {
	return fmt.Errorf("%w: %w", ErrMultibaseDecodeFailed, err)
}

func ErrInvalidVarintWithContext(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidVarint, err)
}

func ErrUnsupportedKeyTypeWithContext(keyType KeyType) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedKeyType, keyType)
}

func ErrInvalidKeySizeWithContext(keyType KeyType, expected, actual int) error {
	return fmt.Errorf("%w for %s: expected %d bytes, got %d", ErrInvalidKeySize, keyType, expected, actual)
}
