package ecarith

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/sw_bn254"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/plonk"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

const (
	ROUND_NR   = 0
	NAME_ECMUL = "ECMUL_INTEGRATION"
)

const (
	// EcMul operation requires 45 rows: 1 operand point and scalar + 1 result point,
	// each point contains 2 scalars (X and Y) of bn254 base field elements (up to
	// 254 bits). Each scalar is divided into 9 31-bit elements of the [koalabear]
	// finite field.
	//
	// Total: 2 points × 2 coordinates × 9 elements + 9 = 45 rows.
	nbRowsPerEcMul = 45
)

// EcMul integrated EC_MUL precompile call verification inside a gnark circuit.
type EcMul struct {
	*EcDataMulSource
	AlignedGnarkData *plonk.Alignment

	size int
	*Limits
}

func NewEcMulZkEvm(comp *wizard.CompiledIOP, limits *Limits) *EcMul {
	return newEcMul(
		comp,
		limits,
		&EcDataMulSource{
			CsEcMul: comp.Columns.GetHandle("ecdata.CIRCUIT_SELECTOR_ECMUL"),
			Limb:    comp.Columns.GetHandle("ecdata.LIMB"),
			Index:   comp.Columns.GetHandle("ecdata.INDEX"),
			IsData:  comp.Columns.GetHandle("ecdata.IS_ECMUL_DATA"),
			IsRes:   comp.Columns.GetHandle("ecdata.IS_ECMUL_RESULT"),
		},
		[]plonk.Option{plonk.WithRangecheck(16, 6, true)},
	)
}

// newEcMul creates a new EC_MUL integration.
func newEcMul(comp *wizard.CompiledIOP, limits *Limits, src *EcDataMulSource, plonkOptions []plonk.Option) *EcMul {
	size := limits.sizeEcMulIntegration()

	toAlign := &plonk.CircuitAlignmentInput{
		Name:               NAME_ECMUL + "_ALIGNMENT",
		Round:              ROUND_NR,
		DataToCircuitMask:  src.CsEcMul,
		DataToCircuit:      src.Limb,
		Circuit:            NewECMulCircuit(limits),
		NbCircuitInstances: limits.NbCircuitInstances,
		PlonkOptions:       plonkOptions,
		InputFiller:        nil, // not necessary: 0 * (0,0) = (0,0) with complete arithmetic
	}
	res := &EcMul{
		EcDataMulSource:  src,
		AlignedGnarkData: plonk.DefineAlignment(comp, toAlign),
		size:             size,
	}

	return res
}

// Assign assigns the data from the trace to the gnark inputs.
func (em *EcMul) Assign(run *wizard.ProverRuntime) {
	em.AlignedGnarkData.Assign(run)
}

// EcDataMulSource is a struct that holds the columns that are used to
// fetch data from the EC_DATA module from the arithmetization.
type EcDataMulSource struct {
	CsEcMul ifaces.Column
	Limb    ifaces.Column
	Index   ifaces.Column
	IsData  ifaces.Column
	IsRes   ifaces.Column
}

// MultiECMulCircuit is a circuit that can handle multiple EC_MUL instances. The
// length of the slice Instances should corresponds to the one defined in the
// Limits struct.
type MultiECMulCircuit struct {
	Instances []ECMulInstance
}

type ECMulInstance struct {
	// We work with the limbs decomposition coming from the arithmetization
	// where the values are split into 9 elements with 31 bits each. The
	// high part is the most significant bits and the low part is the least
	// significant bits. The values are already range checked to be in 31 bit
	// range.

	P_X [9]frontend.Variable `gnark:",public"`
	P_Y [9]frontend.Variable `gnark:",public"`

	N [9]frontend.Variable `gnark:",public"`

	// The result of the multiplication. Is provided by the caller, we have to
	// ensure that the result is correct.
	R_X [9]frontend.Variable `gnark:",public"`
	R_Y [9]frontend.Variable `gnark:",public"`
}

// NewECMulCircuit creates a new circuit for verifying the EC_MUL precompile
// based on the defined number of inputs.
func NewECMulCircuit(limits *Limits) *MultiECMulCircuit {
	return &MultiECMulCircuit{
		Instances: make([]ECMulInstance, limits.NbInputInstances),
	}
}

func (c *MultiECMulCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("field emulation: %w", err)
	}

	s, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("field emulation: %w", err)
	}

	// gnark circuit works with 64 bits values, we need to split the 128 bits
	// values into high and low parts.
	nbInstances := len(c.Instances)
	Ps := make([]sw_bn254.G1Affine, nbInstances)
	Ns := make([]sw_bn254.Scalar, nbInstances)
	Rs := make([]sw_bn254.G1Affine, nbInstances)
	for i := range c.Instances {
		P := sw_bn254.G1Affine{
			X: *f.NewElement(c.Instances[i].P_X[:]),
			Y: *f.NewElement(c.Instances[i].P_Y[:]),
		}

		N := *s.NewElement(c.Instances[i].N[:])

		R := sw_bn254.G1Affine{
			X: *f.NewElement(c.Instances[i].R_X[:]),
			Y: *f.NewElement(c.Instances[i].R_Y[:]),
		}

		Ps[i] = P
		Ns[i] = N
		Rs[i] = R
	}

	curve, err := sw_bn254.Curve(api)
	if err != nil {
		panic(err)
	}

	for i := range Rs {
		res := curve.ScalarMul(&Ps[i], &Ns[i], algopts.WithCompleteArithmetic())
		curve.AssertIsEqual(&Rs[i], res)
	}

	return nil
}
