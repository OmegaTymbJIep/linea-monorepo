//go:build !fuzzlight

package ecarith

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/consensys/linea-monorepo/prover/protocol/compiler/dummy"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/plonk"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/utils/csvtraces"
)

var (

	// 8812078025088706800239420563438698135256154119486538953196282662928678739599
	dummyPx = [9]frontend.Variable{
		"323051151", "575029256", "708815051",
		"1052676050", "496273364", "155891130",
		"715088155", "493291273", "4987",
	}

	// 19384817048585926091202754628019327561583315513931387211365745455438290666381
	dummyPy = [9]frontend.Variable{
		"94815117", "974901648", "411010682",
		"692631405", "507891027", "224020773",
		"493224842", "448434432", "10971",
	}

	// 6392244365320561037829193157981140850021222049710818941199853670416625377985
	dummyScalar = [9]frontend.Variable{
		"622011073", "772182772", "271669167",
		"965949626", "534702776", "133966767",
		"617460883", "947145366", "3617",
	}

	// 18286867191893102909980352899825705524248643499324573950097278735467138404960
	dummyRx = [9]frontend.Variable{
		"146428512", "493202402", "400227789",
		"838888898", "780463447", "489768916",
		"349594366", "43413", "10350",
	}

	// 9901600500795379168368190931083365122151061434285910708538887599132533626517
	dummyRy = [9]frontend.Variable{
		"642029205", "955301831", "60099474",
		"321449211", "634763553", "302633952",
		"114963196", "115192496", "5604",
	}
)

func TestMultiEcMulCircuit(t *testing.T) {
	limits := &Limits{
		NbInputInstances:   2,
		NbCircuitInstances: 0, // not used in this test
	}
	circuit := NewECMulCircuit(limits)
	assignment := NewECMulCircuit(limits)
	instanceAssignment := ECMulInstance{
		P_X: dummyPx,
		P_Y: dummyPy,

		R_X: dummyRx,
		R_Y: dummyRy,

		N: dummyScalar,
	}
	for i := 0; i < limits.NbInputInstances; i++ {
		assignment.Instances[i] = instanceAssignment
	}

	// 403569 constraints
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		circuit,
		assignment,
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.WithBackends(backend.PLONK),
		test.WithCurves(ecc.BLS12_377))

}

func TestEcMulIntegration(t *testing.T) {
	f, err := os.Open("testdata/ecmul_test.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	limits := &Limits{
		NbInputInstances:   3,
		NbCircuitInstances: 2,
	}
	ct, err := csvtraces.NewCsvTrace(f, csvtraces.WithNbRows(limits.sizeEcMulIntegration()))
	if err != nil {
		t.Fatal(err)
	}
	var ecMul *EcMul
	var ecMulSource *EcDataMulSource
	cmp := wizard.Compile(
		func(b *wizard.Builder) {
			ecMulSource = &EcDataMulSource{
				CsEcMul: ct.GetCommit(b, "CS_MUL"),
				Limb:    ct.GetCommit(b, "LIMB"),
				Index:   ct.GetCommit(b, "INDEX"),
				IsData:  ct.GetCommit(b, "IS_DATA"),
				IsRes:   ct.GetCommit(b, "IS_RES"),
			}
			ecMul = newEcMul(b.CompiledIOP, limits, ecMulSource, []plonk.Option{plonk.WithRangecheck(15, 2, true)})
		},
		dummy.Compile,
	)

	proof := wizard.Prove(cmp,
		func(run *wizard.ProverRuntime) {
			ct.Assign(run, "CS_MUL", "LIMB", "INDEX", "IS_DATA", "IS_RES")
			ecMul.Assign(run)
		})

	if err := wizard.Verify(cmp, proof); err != nil {
		t.Fatal("proof failed", err)
	}

	t.Log("proof succeeded")
}
