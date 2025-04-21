package ecdsa

import "slices"

// to30BitLimbs divides a []byte into 30-bit limbs as byte slices.
func to30BitLimbs(data []byte) [][]byte {
	var limbs [][]byte
	bitBuffer := uint64(0)
	bitCount := 0

	for _, b := range data {
		bitBuffer |= uint64(b) << bitCount
		bitCount += 8

		for bitCount >= 30 {
			limb := toByteArray(bitBuffer&0x3FFFFFFF, 4)
			slices.Reverse(limb)
			limbs = append(limbs, limb)
			bitBuffer >>= 30
			bitCount -= 30
		}
	}

	if bitCount > 0 {
		limb := toByteArray(bitBuffer, 4)
		slices.Reverse(limb)
		limbs = append(limbs, limb)
	}

	return limbs
}

func from30BitLimbs(limbs [][]byte) []byte {
	var data []byte
	bitBuffer := uint64(0)
	bitCount := 0

	for _, limb := range limbs {
		slices.Reverse(limb)
		value := uint64(0)
		for i, b := range limb {
			value |= uint64(b) << (8 * i)
		}

		bitBuffer |= value << bitCount
		bitCount += 30

		for bitCount >= 8 {
			data = append(data, byte(bitBuffer&0xFF))
			bitBuffer >>= 8
			bitCount -= 8
		}
	}

	if bitCount > 0 {
		data = append(data, byte(bitBuffer))
	}

	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	return data
}

// toByteArray converts an integer into a byte array of the specified length.
func toByteArray(value uint64, length int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte(value & 0xFF)
		value >>= 8
	}

	for len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}
	return result
}
