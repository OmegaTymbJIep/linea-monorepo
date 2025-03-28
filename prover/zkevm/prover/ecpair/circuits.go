package ecpair

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/emparams"
	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/fields_bn254"
	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/sw_bn254"
)

type (
	fpField   = emulated.Field[emparams.BN254Fp]
	fpElement = emulated.Element[emparams.BN254Fp]
)

// G1ElementWizard represents G1 element as Wizard limbs (2 limbs of 128 bits)
type G1ElementWizard struct {
	P [nbG1Limbs]frontend.Variable
}

// ToG1Element converts G1ElementWizard to G1Affine used in circuit
func (c *G1ElementWizard) ToG1Element(fp *emulated.Field[sw_bn254.BaseField]) sw_bn254.G1Affine {
	return sw_bn254.G1Affine{
		X: *fp.NewElement(reverseEndianness(c.P[:emparams.NbLimbsPerBn254Element])),
		Y: *fp.NewElement(reverseEndianness(c.P[emparams.NbLimbsPerBn254Element:])),
	}
}

// G2ElementWizard represents G2 element as Wizard limbs (4 limbs of 128 bits)
type G2ElementWizard struct {
	Q [nbG2Limbs]frontend.Variable
}

// ToG2Element converts G2ElementWizard to G2Affine used in circuit
func (c *G2ElementWizard) ToG2Element(fp *emulated.Field[sw_bn254.BaseField]) sw_bn254.G2Affine {
	// arithmetization provides G2 coordinates in the following order:
	//   X_Im, X_Re, Y_Im, Y_Re
	// but in gnark we expect
	//   X_Re, X_Im, Y_Re, Y_Im
	// so we need to swap the limbs.
	QX := fields_bn254.E2{
		A0: *fp.NewElement(reverseEndianness(c.Q[emparams.NbLimbsPerBn254Element : emparams.NbLimbsPerBn254Element*2])),
		A1: *fp.NewElement(reverseEndianness(c.Q[:emparams.NbLimbsPerBn254Element])),
	}
	QY := fields_bn254.E2{
		A0: *fp.NewElement(reverseEndianness(c.Q[emparams.NbLimbsPerBn254Element*3 : emparams.NbLimbsPerBn254Element*4])),
		A1: *fp.NewElement(reverseEndianness(c.Q[emparams.NbLimbsPerBn254Element*2 : emparams.NbLimbsPerBn254Element*3])),
	}

	var Q sw_bn254.G2Affine
	Q.P.X = QX
	Q.P.Y = QY

	return Q
}

// GtElementWizard represents Gt element as Wizard limbs (24 limbs of 128 bits)
type GtElementWizard struct {
	T [nbGtLimbs]frontend.Variable
}

// ToGtElement converts GtElementWizard to target group element used in circuit
func (c *GtElementWizard) ToGtElement(fp *emulated.Field[sw_bn254.BaseField]) sw_bn254.GTEl {
	var e12Tower [12]*fpElement

	for i := 0; i < 12; i++ {
		e12Tower[i] = fp.NewElement(reverseEndianness(c.T[emparams.NbLimbsPerBn254Element*i : emparams.NbLimbsPerBn254Element*(i+1)]))
	}

	return intoGtNoTower(fp, e12Tower)
}

// MultiG2GroupcheckCircuit is a circuit that checks multiple G2 group
// membership. Use [newMultiG2GroupcheckCircuit] to create a new instance with
// bounded number of allowed checks.
type MultiG2GroupcheckCircuit struct {
	Instances []G2GroupCheckInstance `gnark:",public"`
}

func newMultiG2GroupcheckCircuit(nbInstances int) *MultiG2GroupcheckCircuit {
	return &MultiG2GroupcheckCircuit{
		Instances: make([]G2GroupCheckInstance, nbInstances),
	}
}

func (c *MultiG2GroupcheckCircuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("new field emulation: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	for i := range c.Instances {
		if err := c.Instances[i].Check(api, fp, pairing); err != nil {
			return fmt.Errorf("instance %d check: %w", i, err)
		}
	}
	return nil
}

// G2GroupCheckInstance is a single instance of G2 group check.
type G2GroupCheckInstance struct {
	Q         G2ElementWizard
	IsSuccess frontend.Variable
}

func (c *G2GroupCheckInstance) Check(api frontend.API, fp *emulated.Field[sw_bn254.BaseField], pairing *sw_bn254.Pairing) error {
	Q := c.Q.ToG2Element(fp)

	isOnG2 := pairing.IsOnG2(&Q)
	api.AssertIsEqual(c.IsSuccess, isOnG2)

	return nil
}

// MultiMillerLoopMulCircuit is a circuit that checks multiple Miller loop
// computation correctness. Use [newMultiMillerLoopMulCircuit] to create a new
// instance with bounded number of allowed checks.
type MultiMillerLoopMulCircuit struct {
	Instances []MillerLoopMulInstance `gnark:",public"`
}

func newMultiMillerLoopMulCircuit(nbInstance int) *MultiMillerLoopMulCircuit {
	return &MultiMillerLoopMulCircuit{
		Instances: make([]MillerLoopMulInstance, nbInstance),
	}
}

func (c *MultiMillerLoopMulCircuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("new field emulation: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	for i := range c.Instances {
		if err := c.Instances[i].Check(fp, pairing); err != nil {
			return fmt.Errorf("instance %d check: %w", i, err)
		}
	}
	return nil
}

// MillerLoopMulInstance is a single instance of Miller loop computation check.
type MillerLoopMulInstance struct {
	Prev    GtElementWizard
	P       G1ElementWizard
	Q       G2ElementWizard
	Current GtElementWizard
}

func (c *MillerLoopMulInstance) Check(fp *emulated.Field[sw_bn254.BaseField], pairing *sw_bn254.Pairing) error {
	P := c.P.ToG1Element(fp)
	Q := c.Q.ToG2Element(fp)
	prev := c.Prev.ToGtElement(fp)
	current := c.Current.ToGtElement(fp)

	pairing.AssertIsOnG2(&Q)
	ml, err := pairing.MillerLoopAndMul(&P, &Q, &prev)
	if err != nil {
		return fmt.Errorf("miller loop and mul: %w", err)
	}
	pairing.AssertIsEqual(&current, ml)

	return nil
}

// MultiMillerLoopFinalExpCircuit is a circuit that checks multiple Miller loop
// and final exponentiation checks. Use [newMultiMillerLoopFinalExpCircuit] to
// create a new instance with bounded number of allowed checks.
type MultiMillerLoopFinalExpCircuit struct {
	Instances []MillerLoopFinalExpInstance `gnark:",public"`
}

func newMultiMillerLoopFinalExpCircuit(nbInstance int) *MultiMillerLoopFinalExpCircuit {
	return &MultiMillerLoopFinalExpCircuit{
		Instances: make([]MillerLoopFinalExpInstance, nbInstance),
	}
}

func (c *MultiMillerLoopFinalExpCircuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("new field emulation: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	for i := range c.Instances {
		if err := c.Instances[i].Check(api, fp, pairing); err != nil {
			return fmt.Errorf("instance %d check: %w", i, err)
		}
	}
	return nil
}

// MillerLoopFinalExpInstance is a single instance of Miller loop and final
// exponentiation check.
type MillerLoopFinalExpInstance struct {
	Prev     GtElementWizard
	P        G1ElementWizard
	Q        G2ElementWizard
	Expected [2]frontend.Variable
}

func (c *MillerLoopFinalExpInstance) Check(api frontend.API, fp *emulated.Field[sw_bn254.BaseField], pairing *sw_bn254.Pairing) error {
	P := c.P.ToG1Element(fp)
	Q := c.Q.ToG2Element(fp)
	prev := c.Prev.ToGtElement(fp)
	api.AssertIsEqual(c.Expected[0], 0)

	expectedIsSuccess := c.Expected[1]

	api.AssertIsBoolean(expectedIsSuccess)
	pairing.AssertIsOnG2(&Q)

	isSuccess := pairing.IsMillerLoopAndFinalExpOne(&P, &Q, &prev)
	api.AssertIsEqual(expectedIsSuccess, isSuccess)

	return nil
}

// intoGtNoTower converts an E12 element as in the outputs of the pairing
// precompile on Ethereum into a non-tower representation of the same E12
// element.
func intoGtNoTower(api *fpField, coordinates [12]*fpElement) sw_bn254.GTEl {

	var (
		C0B0X = coordinates[0]
		C0B0Y = coordinates[1]
		C0B1X = coordinates[2]
		C0B1Y = coordinates[3]
		C0B2X = coordinates[4]
		C0B2Y = coordinates[5]
		C1B0X = coordinates[6]
		C1B0Y = coordinates[7]
		C1B1X = coordinates[8]
		C1B1Y = coordinates[9]
		C1B2X = coordinates[10]
		C1B2Y = coordinates[11]
	)

	var t *fpElement
	t = api.MulConst(C0B0Y, big.NewInt(9))
	c0 := api.Sub(C0B0X, t)
	t = api.MulConst(C1B0Y, big.NewInt(9))
	c1 := api.Sub(C1B0X, t)
	t = api.MulConst(C0B1Y, big.NewInt(9))
	c2 := api.Sub(C0B1X, t)
	t = api.MulConst(C1B1Y, big.NewInt(9))
	c3 := api.Sub(C1B1X, t)
	t = api.MulConst(C0B2Y, big.NewInt(9))
	c4 := api.Sub(C0B2X, t)
	t = api.MulConst(C1B2Y, big.NewInt(9))
	c5 := api.Sub(C1B2X, t)

	return sw_bn254.GTEl{
		A0:  *c0,
		A1:  *c1,
		A2:  *c2,
		A3:  *c3,
		A4:  *c4,
		A5:  *c5,
		A6:  *C0B0Y,
		A7:  *C1B0Y,
		A8:  *C0B1Y,
		A9:  *C1B1Y,
		A10: *C0B2Y,
		A11: *C1B2Y,
	}
}

// reverseEndianness the limbs are provided by the arithmetization in
// big-endian order  but the binary API of gnark manages bits in
// little-endian order.
func reverseEndianness(limbs []frontend.Variable) []frontend.Variable {
	nbLimbs := len(limbs)
	res := make([]frontend.Variable, nbLimbs)

	for i := range limbs {
		res[i] = limbs[nbLimbs-i-1]
	}

	return res
}
