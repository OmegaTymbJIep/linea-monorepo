package emulated

import "math/big"

// Mod1e4096 provides type parametrization for emulated arithmetic over KoalaBear field:
//   - limbs: 137
//   - limb width: 30 bits
//
// The modulus for type parametrisation is 2^4096-1.
//
// This is non-prime modulus. It is mainly targeted for using variable-modulus
// operations (ModAdd, ModMul, ModExp, ModAssertIsEqual) for variable modulus
// arithmetic.
type Mod1e4096 struct{}

func (Mod1e4096) NbLimbs() uint     { return 137 }
func (Mod1e4096) BitsPerLimb() uint { return 30 }
func (Mod1e4096) IsPrime() bool     { return false }
func (Mod1e4096) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}

// Mod1e256 provides type parametrization for emulated arithmetic over KoalaBear field:
//   - limbs: 9
//   - limb width: 30 bits
//
// The modulus for type parametrisation is 2^256-1.
//
// This is non-prime modulus. It is mainly targeted for using variable-modulus
// operations (ModAdd, ModMul, ModExp, ModAssertIsEqual) for variable modulus
// arithmetic.
type Mod1e256 struct{}

func (Mod1e256) NbLimbs() uint     { return 9 }
func (Mod1e256) BitsPerLimb() uint { return 30 }
func (Mod1e256) IsPrime() bool     { return false }
func (Mod1e256) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}
