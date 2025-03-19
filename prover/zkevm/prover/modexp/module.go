package modexp

import (
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/expr_handle"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/plonk"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/projection"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/utils"
)

const (
	// numLimbsPerOperand is the number of rows needed to represent a single operand
	// in the MODEXP module. The operands max size is 4096 bits (Large instance),
	// thus to put into the KoalaBear field we need 4096/30 = 137 limbs, 30 bits each.
	numLimbsPerOperand = 137

	// numLimbsPerSmallOperand is the number of limbs needed to represent a single
	// operand in the small instance of the modexp module. The small instance is
	// 256 bits, thus to put into the KoalaBear field we need 256/30 = 9 limbs,
	// 30 bits each.
	numLimbsPerSmallOperand = 9

	// modexpNumRowsPerInstance is the number of rows present in the MODEXP module
	// to represent a single instance.
	modexpNumRowsPerInstance = numLimbsPerOperand * 4

	// mostSignificantLimbRange is the maximum value that the most significant
	// limb of the modexp operand can take. In both cases (small and large instances)
	// we can have overhead of 14 bits. 137 * 30 - 4096 = 9 * 30 - 256 = 14.
	mostSignificantLimbRange = 1 << (256 - 8*30)

	// nbInstancePerCircuit256 and nbInstancePerCircuit4096 state how many
	// instance of modexp are taken care of by a single gnark circuit in the
	// "small" variant (256 bits) or the "large" variant (4096 bits)
	nbInstancePerCircuit256, nbInstancePerCircuit4096 = 10, 1
)

// Module implements the wizard part responsible for checking the MODEXP
// claims coming from the BLKMDXP module of the arithmetization.
type Module struct {
	// MaxNb256BitsInstances MaxNb4096BitsInstances corresponds to the maximum
	// number of instances that we want to support for the corresponding variant
	// of the Modexp circuit.
	MaxNb256BitsInstances, MaxNb4096BitsInstances int
	// Input stores the columns used as a source for the antichamber.
	Input Input
	// IsActive is a binary indicator column marking with a 1, the rows of the
	// antichamber modules corresponding "active" rows: e.g. NOT padding rows.
	IsActive ifaces.Column
	// IsSmall, IsLarge are indicator columns that are constant per modexp
	// instances. They are mutually exclusive and
	IsSmall, IsLarge ifaces.Column
	// Limb contains the modexp arguments and is subjected to a projection
	// constraint from the BLK_MDXP (using IsActive as filter). It is constrained
	// to zero when IsActive = 0.
	Limbs ifaces.Column
	// LsbIndicator is a precomputed column marking with a 1 the last 9 limbs
	// of every operand, this limbs correspond to the small instance of the
	// modexp. The column is precomputed because all Modexp provided by the
	// arithmetization have exactly the same layout.
	LsbIndicator ifaces.Column
	// MostSignifLimbIndicator is a precomputed column marking with a 1 the last
	// limb of every operand. The column is precomputed because all Modexp provided
	// by the arithmetization have exactly the same layout.
	MostSignifLimbIndicator ifaces.Column
	// PeriodicSampleIndicator is a precomputed column marking with a 1 the first
	// row of every modexp instance. The column is precomputed because all Modexp
	// provided by the arithmetization have exactly the same layout.
	PeriodicSampleIndicator ifaces.Column
	// ToSmallCirc and ToLargeCirc are indicator columns marking with a 1 the
	// positions of limbs corresponding to public inputs of (respectely) the
	// small and the large circuit.
	ToSmallCirc ifaces.Column
	// connection logic of the modexp circuit specialized for the small and
	// large instances respectively
	GnarkCircuitConnector256Bits, GnarkCircuitConnector4096Bits *plonk.Alignment
	// hasCircuit indicates whether the circuit has been set in the module. In
	// production, it will be always set to true. But for convenience we omit
	// the circuit in some of the test as this is CPU intensive.
	hasCircuit bool
}

// NewModuleZkEvm constructs an instance of the modexp module. It should be called
// only once.
//
// To define the circuit, call [Module.WithCircuit] as the present function
// does not define them.
func NewModuleZkEvm(comp *wizard.CompiledIOP, settings Settings) *Module {
	return newModule(comp, newZkEVMInput(comp, settings)).
		WithCircuit(comp, plonk.WithRangecheck(15, 2, false))
}

func newModule(comp *wizard.CompiledIOP, input Input) *Module {

	var (
		settings      = input.Settings
		maxNbInstance = settings.MaxNbInstance256 + settings.MaxNbInstance4096
		size          = utils.NextPowerOfTwo(maxNbInstance * modexpNumRowsPerInstance)
		mod           = &Module{
			Input:                  input,
			MaxNb256BitsInstances:  settings.MaxNbInstance256,
			MaxNb4096BitsInstances: settings.MaxNbInstance4096,
			IsActive:               comp.InsertCommit(0, "MODEXP_IS_ACTIVE", size),
			Limbs:                  comp.InsertCommit(0, "MODEXP_LIMBS", size),
			IsSmall:                comp.InsertCommit(0, "MODEXP_IS_SMALL", size),
			IsLarge:                comp.InsertCommit(0, "MODEXP_IS_LARGE", size),
			LsbIndicator:           comp.InsertPrecomputed("MODEXP_LSB_INDICATOR", lsbIndicatorValue(size)),
			PeriodicSampleIndicator: comp.InsertPrecomputed("MODEXP_PERIODIC_SAMPLE_INDICATOR",
				periodicSampleIndicatorValue(size)),
			MostSignifLimbIndicator: comp.InsertPrecomputed("MODEXP_LSB_MOST_SIGNIF_LIMB_INDICATOR",
				mostSignifLimbIndicatorValue(size)),
			ToSmallCirc: comp.InsertCommit(0, "MODEXP_TO_SMALL_CIRC", size),
		}
	)

	mod.Input.setIsModexp(comp)

	mod.csIsActive(comp)
	mod.csIsSmallAndLarge(comp)
	mod.csToCirc(comp)
	mod.csLimbsRange(comp)

	projection.InsertProjection(
		comp,
		"MODEXP_BLKMDXP_PROJECTION",
		[]ifaces.Column{mod.Input.Limbs},
		[]ifaces.Column{mod.Limbs},
		mod.Input.isModExp,
		mod.IsActive,
	)

	return mod
}

// WithCircuit adds the Plonk-in-Wizard circuit verification to complete
// the anti-chamber.
func (mod *Module) WithCircuit(comp *wizard.CompiledIOP, options ...plonk.Option) *Module {

	mod.hasCircuit = true

	mod.GnarkCircuitConnector256Bits = plonk.DefineAlignment(
		comp,
		&plonk.CircuitAlignmentInput{
			Name:               "MODEXP_256_BITS",
			DataToCircuit:      mod.Limbs,
			DataToCircuitMask:  mod.ToSmallCirc,
			Circuit:            allocateCircuit(nbInstancePerCircuit256, 256),
			NbCircuitInstances: utils.DivCeil(mod.MaxNb256BitsInstances, nbInstancePerCircuit256),
			PlonkOptions:       options,
		},
	)

	mod.GnarkCircuitConnector4096Bits = plonk.DefineAlignment(
		comp,
		&plonk.CircuitAlignmentInput{
			Name:               "MODEXP_4096_BITS",
			DataToCircuit:      mod.Limbs,
			DataToCircuitMask:  mod.IsLarge,
			Circuit:            allocateCircuit(nbInstancePerCircuit4096, 4096),
			NbCircuitInstances: utils.DivCeil(mod.MaxNb4096BitsInstances, nbInstancePerCircuit4096),
			PlonkOptions:       options,
		},
	)

	return mod
}

// lsbIndicatorValue returns the smartvector corresponding to the given size.
// It is constructed the same pattern every 137 field elements which
// corresponds to 9 1s followed by 128 (137 - 9) zeroes.
func lsbIndicatorValue(size int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)
	for i := range resSlice {
		if i%numLimbsPerOperand >= numLimbsPerOperand-numLimbsPerSmallOperand {
			resSlice[i].SetOne()
		}
	}
	return smartvectors.NewRegular(resSlice)
}

// periodicSampleIndicatorValue returns the smartvector corresponding to the
// given size. It ocnstructs a vector that contains 1 every modexpNumRowsPerInstance
// elements, inidicating the start of a new modexp instance. The behavior is
// similar to the variables.NewPeriodicSample, but the period isn't power of 2.
func periodicSampleIndicatorValue(size int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)
	for i := range resSlice {
		if i%modexpNumRowsPerInstance == 0 {
			resSlice[i].SetOne()
		}
	}
	return smartvectors.NewRegular(resSlice)
}

// mostSignifLimbIndicatorValue creates a smartvector where the elements at positions
// corresponding to the most significant limb of each operand set to 1. These
// positions occur every 137 elements starting from the 0 position and starting
// from the 128 (137 - 9) position.
func mostSignifLimbIndicatorValue(size int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)

	for i := 0; i < size; i += numLimbsPerOperand {
		resSlice[i].SetOne()
	}

	firstMostSignificantLimb := numLimbsPerOperand - numLimbsPerSmallOperand - 1
	for i := firstMostSignificantLimb; i < size; i += numLimbsPerOperand {
		resSlice[i].SetOne()
	}

	return smartvectors.NewRegular(resSlice)
}

// csIsActive ensures that the ant.IsActive column is well constructed and that
// all the other columns are zero when it is zero.
func (mod *Module) csIsActive(comp *wizard.CompiledIOP) {

	mustBeBinary(comp, mod.IsActive)

	comp.InsertGlobal(
		0,
		"MODEXP_IS_ACTIVE_DOES_NOT_INCREASE",
		sym.Mul(
			mod.IsActive,
			sym.Sub(mod.IsActive, column.Shift(mod.IsActive, -1)),
		),
	)

	//
	// NB: IsActive can only have a multiple of 128 1's. That's because it is
	// not supposed to go off in the middle of an actual modexp instance.
	// However, this is pre-enforced by the fact that this column is used as
	// the indicator of a projection query linking the blk_mdxp module with
	// the antichamber.
	//
	// This implictly constrains that aspect and thus, it does not require
	// a particular constraint.
	//

	mustCancelWhenBinCancel(comp, mod.IsActive, mod.Limbs)
}

// csIsSmallAndLarge constrains IsSmall and IsLarge
func (mod *Module) csIsSmallAndLarge(comp *wizard.CompiledIOP) {

	mustBeBinary(comp, mod.IsSmall)
	mustBeBinary(comp, mod.IsLarge)

	comp.InsertGlobal(
		0,
		ifaces.QueryIDf("MODEXP_IS_SMALL_LARGE_ARE_MUTUALLY_EXCLUSIVE"),
		sym.Sub(
			mod.IsActive,
			sym.Add(mod.IsSmall, mod.IsLarge),
		),
	)

	//
	// NB: The facts that
	// * IsSmall and IsLarge are mutually exclusive columns
	// * that IsActive implictly only switches at the end of the last modexp
	// instance (see the comment in the [csIsActive] function).
	// * The constraint [MODEXP_IS_SMALL_CONSTANT_BY_SEGMENT] is here
	//
	// Imply already an equivalent [MODEXP_IS_LARGE_CONSTANT_BY_SEGMENT]
	// constraint. So we do not need to declare it.
	//

	comp.InsertGlobal(
		0,
		"MODEXP_IS_SMALL_CONSTANT_BY_SEGMENT",
		sym.Mul(
			sym.Sub(1, mod.PeriodicSampleIndicator),
			sym.Sub(mod.IsSmall, column.Shift(mod.IsSmall, -1)),
		),
	)

	//
	// The constraint below ensures that if the IS_SMALL flag is set, then the
	// limbs 2..32 of the operands of the corresponding modexp must be zero
	// (otherwise, they would represent numbers larger than 256 bits).
	//
	// The converse constraint does not exists in the 4096 case because it would
	// not be wrong to supply
	//

	comp.InsertGlobal(
		0,
		"MODEXP_IS_SMALL_IMPLIES_SMALL_OPERANDS",
		sym.Mul(
			mod.Limbs,
			mod.IsSmall,
			sym.Sub(1, mod.LsbIndicator),
		),
	)
}

// csToCirc ensures the well-construction of ant.ToSmallCirc
func (mod *Module) csToCirc(comp *wizard.CompiledIOP) {

	comp.InsertGlobal(
		0,
		"MODEXP_TO_SMALL_CIRC_VAL",
		sym.Sub(
			mod.ToSmallCirc,
			sym.Mul(
				mod.IsSmall,
				mod.LsbIndicator,
			),
		),
	)

	//
	// NB: We set ToLargeCirc = IsLarge as these to indicator coincidates
	// so there is no need to add extra constraints.
	//
}

// csLimbsRange constrains the limbs of the modexp module
func (mod *Module) csLimbsRange(comp *wizard.CompiledIOP) {
	//
	// The constraints below ensures that the most significant limb of the
	// operands does not exceed 16 bytes. This is necessary because using
	// 30 bit limbs one will have a 14 bit overhead in the most significant
	// limb (in case of 256 and 4096 bits operands), so we need to check
	// that they aren't used.
	//

	msli := mod.MostSignifLimbIndicator
	smsli := column.Shift(msli, numLimbsPerSmallOperand-numLimbsPerOperand)

	// results in 0 if it is a large instance and the most significant limb is set.
	smallInLargeCheck := sym.Sub(1, sym.Mul(mod.IsLarge, sym.Mul(msli, sym.Sub(1, smsli))))

	mostSignifLimbCol := expr_handle.ExprHandle(
		comp,
		sym.Mul(mod.Limbs, msli, smallInLargeCheck),
		"MODEXP_MOST_SIGNIFICANT_LIMB",
	)

	comp.InsertRange(
		0,
		"MODEXP_RANGE_MOST_SIGNIFICANT_LIMB",
		mostSignifLimbCol,
		mostSignificantLimbRange,
	)
}

// mustBeBinary constraints c to be binary
func mustBeBinary(comp *wizard.CompiledIOP, c ifaces.Column) {

	comp.InsertGlobal(
		0,
		ifaces.QueryIDf("%v_CANCEL_IS_BINARY", c.GetColID()),
		sym.Mul(c, sym.Sub(c, 1)),
	)
}

// mustCancelWhenBinCancel enforces to 'c' to be zero when the binary column
// `bin` is zero. The constraint does not work if bin is not constrained to be
// binary.
func mustCancelWhenBinCancel(comp *wizard.CompiledIOP, bin, c ifaces.Column) {

	comp.InsertGlobal(
		0,
		ifaces.QueryIDf("%v_CANCEL_WHEN_NOT_%v", c.GetColID(), bin.GetColID()),
		sym.Mul(
			sym.Sub(1, bin),
			c,
		),
	)
}
