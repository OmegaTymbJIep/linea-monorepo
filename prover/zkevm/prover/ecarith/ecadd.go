package ecarith

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/sw_bn254"

	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/plonk"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

const (
	NAME_ECADD = "ECADD_INTEGRATION"
)

const (
	// EcAdd operation requires 54 rows: 2 operand points and 1 result point, each
	// containing 2 coordinates (X and Y) of bn254 base field elements (up to 254
	// bits). Each coordinate is divided into 9 30-bit elements of the KoalaBear
	// finite field.
	//
	// Total: 3 points × 2 coordinates × 9 elements = 54 rows.
	nbRowsPerEcAdd = 54
)

// EcAdd integrates EC_ADD precompile call verification inside a gnark circuit.
type EcAdd struct {
	*EcDataAddSource
	AlignedGnarkData *plonk.Alignment

	size int
	*Limits
}

func NewEcAddZkEvm(comp *wizard.CompiledIOP, limits *Limits) *EcAdd {
	return newEcAdd(
		comp,
		limits,
		&EcDataAddSource{
			CsEcAdd: comp.Columns.GetHandle("ecdata.CIRCUIT_SELECTOR_ECADD"),
			Limb:    comp.Columns.GetHandle("ecdata.LIMB"),
			Index:   comp.Columns.GetHandle("ecdata.INDEX"),
			IsData:  comp.Columns.GetHandle("ecdata.IS_ECADD_DATA"),
			IsRes:   comp.Columns.GetHandle("ecdata.IS_ECADD_RESULT"),
		},
		[]plonk.Option{plonk.WithRangecheck(15, 2, true)},
	)
}

// newEcAdd creates a new EC_ADD integration.
func newEcAdd(comp *wizard.CompiledIOP, limits *Limits, src *EcDataAddSource, plonkOptions []plonk.Option) *EcAdd {
	size := limits.sizeEcAddIntegration()

	toAlign := &plonk.CircuitAlignmentInput{
		Name:               NAME_ECADD + "_ALIGNMENT",
		Round:              ROUND_NR,
		DataToCircuitMask:  src.CsEcAdd,
		DataToCircuit:      src.Limb,
		Circuit:            NewECAddCircuit(limits),
		NbCircuitInstances: limits.NbCircuitInstances,
		PlonkOptions:       plonkOptions,
		InputFiller:        nil, // not necessary: 0 * (0,0) = (0,0) with complete arithmetic
	}
	res := &EcAdd{
		EcDataAddSource:  src,
		AlignedGnarkData: plonk.DefineAlignment(comp, toAlign),
		size:             size,
	}

	return res
}

// Assign assigns the data from the trace to the gnark inputs.
func (em *EcAdd) Assign(run *wizard.ProverRuntime) {
	em.AlignedGnarkData.Assign(run)
}

// EcDataAddSource is a struct that holds the columns that are used to
// fetch data from the EC_DATA module from the arithmetization.
type EcDataAddSource struct {
	CsEcAdd ifaces.Column
	Limb    ifaces.Column
	Index   ifaces.Column
	IsData  ifaces.Column
	IsRes   ifaces.Column
}

// MultiECAddCircuit is a circuit that can handle multiple EC_ADD instances. The
// length of the slice Instances should corresponds to the one defined in the
// Limits struct.
type MultiECAddCircuit struct {
	Instances []ECAddInstance
}

type ECAddInstance struct {
	// First input to addition
	P_X [9]frontend.Variable `gnark:",public"`
	P_Y [9]frontend.Variable `gnark:",public"`

	// Second input to addition
	Q_X [9]frontend.Variable `gnark:",public"`
	Q_Y [9]frontend.Variable `gnark:",public"`

	// The result of the addition. Is provided non-deterministically by the
	// caller, we have to ensure that the result is correct.
	R_X [9]frontend.Variable `gnark:",public"`
	R_Y [9]frontend.Variable `gnark:",public"`
}

// NewECAddCircuit creates a new circuit for verifying the EC_ADD precompile
// based on the defined number of inputs.
func NewECAddCircuit(limits *Limits) *MultiECAddCircuit {
	return &MultiECAddCircuit{
		Instances: make([]ECAddInstance, limits.NbInputInstances),
	}
}

func (c *MultiECAddCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("field emulation: %w", err)
	}

	// gnark circuit works with 64 bits values, we need to split the 128 bits
	// values into high and low parts.
	nbInstances := len(c.Instances)
	Ps := make([]sw_bn254.G1Affine, nbInstances)
	Qs := make([]sw_bn254.G1Affine, nbInstances)
	Rs := make([]sw_bn254.G1Affine, nbInstances)
	for i := range c.Instances {
		P := sw_bn254.G1Affine{
			X: *f.NewElement(c.Instances[i].P_X[:]),
			Y: *f.NewElement(c.Instances[i].P_Y[:]),
		}

		Q := sw_bn254.G1Affine{
			X: *f.NewElement(c.Instances[i].Q_X[:]),
			Y: *f.NewElement(c.Instances[i].Q_Y[:]),
		}

		R := sw_bn254.G1Affine{
			X: *f.NewElement(c.Instances[i].R_X[:]),
			Y: *f.NewElement(c.Instances[i].R_Y[:]),
		}

		Ps[i] = P
		Qs[i] = Q
		Rs[i] = R
	}

	curve, err := sw_bn254.Curve(api)
	if err != nil {
		panic(err)
	}

	for i := range Rs {
		res := curve.AddUnified(&Ps[i], &Qs[i])
		curve.AssertIsEqual(&Rs[i], res)
	}

	return nil
}
