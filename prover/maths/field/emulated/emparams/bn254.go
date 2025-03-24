package emparams

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// NbLimbsPerBn254Element to represent a single field element
// (either fp or fr) we need 9 limbs of 30 bits each.
const NbLimbsPerBn254Element = 9

// BN254Fp implements the [emulated.FieldParams] interface to emulate
// the bn254 base field in the [koalabear] field.
type BN254Fp struct{}

func (BN254Fp) NbLimbs() uint     { return NbLimbsPerBn254Element }
func (BN254Fp) BitsPerLimb() uint { return NbBitsPerLimb }
func (BN254Fp) IsPrime() bool     { return true }
func (BN254Fp) Modulus() *big.Int { return ecc.BN254.BaseField() }

// BN254Fr implements the [emulated.FieldParams] interface to emulate
// the bn254 scalar field in the [koalabear] field.
type BN254Fr struct{}

func (BN254Fr) NbLimbs() uint     { return NbLimbsPerBn254Element }
func (BN254Fr) BitsPerLimb() uint { return NbBitsPerLimb }
func (BN254Fr) IsPrime() bool     { return true }
func (BN254Fr) Modulus() *big.Int { return ecc.BN254.ScalarField() }
