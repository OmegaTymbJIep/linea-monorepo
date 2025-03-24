package sw_bn254

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/emparams"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[emparams.BN254Fp]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[emparams.BN254Fr]

// Curve returns a new emulated curve defined over the bn254 base and scalar
// fields.
func Curve(api frontend.API) (*sw_emulated.Curve[emparams.BN254Fp, emparams.BN254Fr], error) {
	return sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
}

// ScalarField is the [emulated.FieldParams] implementation of the curve scalar field.
type ScalarField = emparams.BN254Fr

// BaseField is the [emulated.FieldParams] implementation of the curve base field.
type BaseField = emparams.BN254Fp
