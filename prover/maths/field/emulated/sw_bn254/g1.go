package sw_bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// NbLimbsPerElement to represent a single field element
// (either fp or fr) we need 9 limbs of 30 bits each.
const NbLimbsPerElement = 9

// NbBitsPerLimb is the number of bits in a single limb.
const NbBitsPerLimb = 30

// BaseField implements the [emulated.FieldParams] interface to emulate
// the bn254 base field in the [koalabear] field.
type BaseField struct{}

func (BaseField) NbLimbs() uint     { return 9 }
func (BaseField) BitsPerLimb() uint { return 30 }
func (BaseField) IsPrime() bool     { return true }
func (BaseField) Modulus() *big.Int { return ecc.BN254.BaseField() }

// ScalarField implements the [emulated.FieldParams] interface to emulate
// the bn254 scalar field in the [koalabear] field.
type ScalarField struct{}

func (ScalarField) NbLimbs() uint     { return 9 }
func (ScalarField) BitsPerLimb() uint { return 30 }
func (ScalarField) IsPrime() bool     { return true }
func (ScalarField) Modulus() *big.Int { return ecc.BN254.ScalarField() }

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

// Curve returns a new emulated curve defined over the bn254 base and scalar
// fields.
func Curve(api frontend.API) (*sw_emulated.Curve[BaseField, ScalarField], error) {
	return sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBN254Params())
}
