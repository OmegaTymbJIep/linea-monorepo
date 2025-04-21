package ecdsa

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLimbDivision(t *testing.T) {
	cases := []string{
		//"5f0a24ed04792b90c620e5c2121c16ad23a986b811f2c40c92b54f1e93d46e81",
		//"1eea6fb19e36ef8926c9f9a00a4185a0469015343da496de5dca17845e4a0e80",
		//"b2e17f39d52e04340f4041e4ceb2b02884406893",
		//"12",
	}

	for _, c := range cases {
		bytes, err := hex.DecodeString(c)
		if err != nil {
			t.Error(err)
		}

		limbs := to30BitLimbs(bytes)
		merged := from30BitLimbs(limbs)

		assert.Equal(t, bytes, merged)
	}
}
