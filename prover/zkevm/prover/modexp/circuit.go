package modexp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/emparams"
	"github.com/consensys/linea-monorepo/prover/utils"
)

const (
	// bit-size bound for the operands in the small
	smallModexpSize = 256
	largeModexpSize = 4096
)

// modexpCircuit implements the [frontend.Circuit] interface and is responsible
// for ensuring all the modexp claims brought to the antichamber module.
//
// The circuit is meant to be used in two variants:
//   - 256 bits, where all the operands and the claimed result have a size
//     smaller than 256 bits.
//   - 4096, where the operands are bound to 4096 bits
type modexpCircuit struct {
	Instances []modexpCircuitInstance `gnark:",public"`
}

// modexpCircuitInstance is a substructre interface and is
// responsible for ensuring the correctness of the evaluation of the MODEXP
// precompile for a single instance of MODEXP.
//
// The operands are represented in limbs of 16 bytes.
type modexpCircuitInstance struct {
	Base     []frontend.Variable `gnark:",public"`
	Exponent []frontend.Variable `gnark:",public"`
	Modulus  []frontend.Variable `gnark:",public"`
	Result   []frontend.Variable `gnark:",public"`
}

// allocate256Bits allocates [modexpCircuit] for n instances assuming the 256-bit
// variant.
func allocateCircuit(n int, numBits int) *modexpCircuit {
	var (
		numLimbs int
		res      = &modexpCircuit{
			Instances: make([]modexpCircuitInstance, n),
		}
	)

	switch numBits {
	case smallModexpSize:
		numLimbs = numLimbsPerSmallOperand
	case largeModexpSize:
		numLimbs = numLimbsPerOperand
	default:
		utils.Panic("expected `numBits = {%v, %v}`", smallModexpSize, largeModexpSize)
	}

	for i := range res.Instances {
		res.Instances[i].Base = make([]frontend.Variable, numLimbs)
		res.Instances[i].Exponent = make([]frontend.Variable, numLimbs)
		res.Instances[i].Modulus = make([]frontend.Variable, numLimbs)
		res.Instances[i].Result = make([]frontend.Variable, numLimbs)
	}

	return res
}

// Define implements the [frontend.Circuit] interface
func (m *modexpCircuit) Define(api frontend.API) error {

	for i := range m.Instances {

		var (
			instance = m.Instances[i]
			numLimbs = len(m.Instances[i].Base)
		)

		switch numLimbs {
		case numLimbsPerSmallOperand:
			checkModexpInstance[emparams.Mod1e256](api, &instance)
		case numLimbsPerOperand:
			checkModexpInstance[emparams.Mod1e4096](api, &instance)
		default:
			utils.Panic(
				"Unexpected limbs number = %v, should be either %v or %v",
				numLimbs, numLimbsPerSmallOperand, numLimbsPerOperand,
			)
		}
	}

	return nil
}

// defined4096 implements the circuit logic for the case where
func checkModexpInstance[P emulated.FieldParams](api frontend.API, m *modexpCircuitInstance) {

	var (
		params        P
		emApi, errAPI = emulated.NewField[P](api)
		baseLimbs     = make([]frontend.Variable, params.NbLimbs())
		exponentLimbs = make([]frontend.Variable, params.NbLimbs())
		modulusLimbs  = make([]frontend.Variable, params.NbLimbs())
		resultLimbs   = make([]frontend.Variable, params.NbLimbs())
	)

	if errAPI != nil {
		utils.Panic("could not generate the API: %v", errAPI)
	}

	// The limbs are provided by the arithmetization in big-endian order
	// but the binary API of gnark manages bits in little-endian order.
	posInLimbs := params.NbLimbs()
	for i := range params.NbLimbs() {
		posInLimbs -= 1
		baseLimbs[posInLimbs] = m.Base[i]
		exponentLimbs[posInLimbs] = m.Exponent[i]
		modulusLimbs[posInLimbs] = m.Modulus[i]
		resultLimbs[posInLimbs] = m.Result[i]
	}

	var (
		base           = emApi.NewElement(baseLimbs)
		exponent       = emApi.NewElement(exponentLimbs)
		modulus        = emApi.NewElement(modulusLimbs)
		resultExpected = emApi.NewElement(resultLimbs)
		resultActual   = evmprecompiles.Expmod(api, base, exponent, modulus)
	)

	emApi.AssertIsEqual(resultExpected, resultActual)
}
