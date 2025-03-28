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
		"4987", "493291273", "715088155",
		"155891130", "496273364", "1052676050",
		"708815051", "575029256", "323051151",
	}

	// 19384817048585926091202754628019327561583315513931387211365745455438290666381
	dummyPy = [9]frontend.Variable{
		"10971", "448434432", "493224842",
		"224020773", "507891027", "692631405",
		"411010682", "974901648", "94815117",
	}

	// 6392244365320561037829193157981140850021222049710818941199853670416625377985
	dummyScalar = [9]frontend.Variable{
		"3617", "947145366", "617460883",
		"133966767", "534702776", "965949626",
		"271669167", "772182772", "622011073",
	}

	// 18286867191893102909980352899825705524248643499324573950097278735467138404960
	dummyRx = [9]frontend.Variable{
		"10350", "43413", "349594366",
		"489768916", "780463447", "838888898",
		"400227789", "493202402", "146428512",
	}

	// 9901600500795379168368190931083365122151061434285910708538887599132533626517
	dummyRy = [9]frontend.Variable{
		"5604", "115192496", "114963196",
		"302633952", "634763553", "321449211",
		"60099474", "955301831", "642029205",
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
