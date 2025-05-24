package didkey

import "fmt"

// encodeMulticodec encodes a multicodec value using unsigned varint encoding
func encodeMulticodec(codec uint64) []byte {
	var result []byte

	for codec >= 0x80 {
		result = append(result, byte(codec)|0x80)
		codec >>= 7
	}
	result = append(result, byte(codec))

	return result
}

// decodeMulticodec decodes a multicodec value from bytes using unsigned varint encoding
// Returns the decoded value and the number of bytes consumed
func decodeMulticodec(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data")
	}

	var value uint64
	var shift uint
	var bytesRead int

	for i, b := range data {
		bytesRead = i + 1

		value |= uint64(b&0x7F) << shift

		if b&0x80 == 0 {
			return value, bytesRead, nil
		}

		shift += 7
		if shift >= 64 {
			return 0, 0, fmt.Errorf("multicodec value too large")
		}
	}

	return 0, 0, fmt.Errorf("incomplete varint")
}

// getMulticodecForKeyType returns the multicodec identifier for a given key type
func getMulticodecForKeyType(keyType KeyType) (uint64, error) {
	switch keyType {
	case KeyTypeEd25519:
		return MulticodecEd25519Pub, nil
	case KeyTypeX25519:
		return MulticodecX25519Pub, nil
	case KeyTypeSecp256k1:
		return MulticodecSecp256k1Pub, nil
	case KeyTypeBLS12381G1:
		return MulticodecBLS12381G1Pub, nil
	case KeyTypeBLS12381G2:
		return MulticodecBLS12381G2Pub, nil
	case KeyTypeP256:
		return MulticodecP256Pub, nil
	case KeyTypeP384:
		return MulticodecP384Pub, nil
	default:
		return 0, NewError("encode", fmt.Sprintf("unsupported key type: %s", keyType))
	}
}

// getKeyTypeForMulticodec returns the key type for a given multicodec identifier
func getKeyTypeForMulticodec(codec uint64) (KeyType, error) {
	switch codec {
	case MulticodecEd25519Pub:
		return KeyTypeEd25519, nil
	case MulticodecX25519Pub:
		return KeyTypeX25519, nil
	case MulticodecSecp256k1Pub:
		return KeyTypeSecp256k1, nil
	case MulticodecBLS12381G1Pub:
		return KeyTypeBLS12381G1, nil
	case MulticodecBLS12381G2Pub:
		return KeyTypeBLS12381G2, nil
	case MulticodecP256Pub:
		return KeyTypeP256, nil
	case MulticodecP384Pub:
		return KeyTypeP384, nil
	default:
		return "", NewError("decode", fmt.Sprintf("unsupported multicodec: 0x%x", codec))
	}
}

// encodeMulticodecKey encodes a key with its multicodec prefix
func encodeMulticodecKey(keyType KeyType, keyBytes []byte) ([]byte, error) {
	codec, err := getMulticodecForKeyType(keyType)
	if err != nil {
		return nil, err
	}

	codecBytes := encodeMulticodec(codec)
	result := make([]byte, len(codecBytes)+len(keyBytes))
	copy(result, codecBytes)
	copy(result[len(codecBytes):], keyBytes)

	return result, nil
}

// decodeMulticodecKey decodes a key with its multicodec prefix
func decodeMulticodecKey(data []byte) (KeyType, []byte, error) {
	if len(data) == 0 {
		return "", nil, NewError("decode", "empty data")
	}

	codec, bytesRead, err := decodeMulticodec(data)
	if err != nil {
		return "", nil, NewError("decode", fmt.Sprintf("failed to decode multicodec: %v", err))
	}

	keyType, err := getKeyTypeForMulticodec(codec)
	if err != nil {
		return "", nil, err
	}

	keyBytes := data[bytesRead:]
	return keyType, keyBytes, nil
}
