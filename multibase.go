package didkey

import (
	"fmt"
	"strings"
)

const (
	// Base58BTCAlphabet is the alphabet used for base58-btc encoding
	Base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// MultibaseBase58BTCPrefix is the prefix for base58-btc multibase encoding
	MultibaseBase58BTCPrefix = "z"
)

// encodeBase58BTC encodes bytes to base58-btc
func encodeBase58BTC(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Convert to big integer
	num := make([]byte, len(data))
	copy(num, data)

	// Count leading zeros
	leadingZeros := 0
	for i := 0; i < len(data) && data[i] == 0; i++ {
		leadingZeros++
	}

	// Encode
	encoded := []byte{}
	base := len(Base58BTCAlphabet)

	for len(num) > 0 {
		remainder := 0
		for i := 0; i < len(num); i++ {
			temp := remainder*256 + int(num[i])
			num[i] = byte(temp / base)
			remainder = temp % base
		}
		encoded = append([]byte{Base58BTCAlphabet[remainder]}, encoded...)

		// Remove leading zeros from num
		for len(num) > 0 && num[0] == 0 {
			num = num[1:]
		}
	}

	// Add leading zeros as '1's
	for i := 0; i < leadingZeros; i++ {
		encoded = append([]byte{Base58BTCAlphabet[0]}, encoded...)
	}

	return string(encoded)
}

// decodeBase58BTC decodes a base58-btc string to bytes
func decodeBase58BTC(encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte{}, nil
	}

	// Count leading ones
	leadingOnes := 0
	for i := 0; i < len(encoded) && encoded[i] == Base58BTCAlphabet[0]; i++ {
		leadingOnes++
	}

	// Decode
	decoded := []byte{0}
	base := len(Base58BTCAlphabet)

	for _, char := range encoded {
		index := strings.IndexRune(Base58BTCAlphabet, char)
		if index == -1 {
			return nil, fmt.Errorf("invalid character '%c' in base58 string", char)
		}

		carry := index
		for i := len(decoded) - 1; i >= 0; i-- {
			carry += int(decoded[i]) * base
			decoded[i] = byte(carry % 256)
			carry /= 256
		}

		for carry > 0 {
			decoded = append([]byte{byte(carry % 256)}, decoded...)
			carry /= 256
		}
	}

	// Add leading zeros
	for i := 0; i < leadingOnes; i++ {
		decoded = append([]byte{0}, decoded...)
	}

	return decoded, nil
}

// encodeMultibase encodes bytes to multibase with base58-btc encoding
func encodeMultibase(data []byte) string {
	return MultibaseBase58BTCPrefix + encodeBase58BTC(data)
}

// decodeMultibase decodes a multibase string with base58-btc encoding
func decodeMultibase(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, MultibaseBase58BTCPrefix) {
		return nil, fmt.Errorf("invalid multibase prefix, expected '%s'", MultibaseBase58BTCPrefix)
	}

	base58Data := encoded[len(MultibaseBase58BTCPrefix):]
	return decodeBase58BTC(base58Data)
}
