package ecpair

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/maths/field/emulated/emparams"
	"github.com/consensys/linea-monorepo/prover/utils"
)

// recomposeFp recomposes a big.Int from a slice of 30 bit limbs.
func recomposeFp(limbs []field.Element, res *fp.Element) {
	var buf, resBigInt big.Int

	for _, limb := range limbs {
		resBigInt.Lsh(&resBigInt, emparams.NbBitsPerLimb)
		resBigInt.Add(&resBigInt, limb.BigInt(&buf))
	}

	res.SetBigInt(&resBigInt)
}

func convG2WizardToGnark(limbs [nbG2Limbs]field.Element) bn254.G2Affine {
	var res bn254.G2Affine

	recomposeFp(limbs[:emparams.NbLimbsPerBn254Element], &res.X.A1)
	recomposeFp(limbs[emparams.NbLimbsPerBn254Element:emparams.NbLimbsPerBn254Element*2], &res.X.A0)
	recomposeFp(limbs[emparams.NbLimbsPerBn254Element:emparams.NbLimbsPerBn254Element*3], &res.Y.A1)
	recomposeFp(limbs[emparams.NbLimbsPerBn254Element:], &res.Y.A0)

	return res
}

func convG1WizardToGnark(limbs [nbG1Limbs]field.Element) bn254.G1Affine {
	var res bn254.G1Affine

	recomposeFp(limbs[:emparams.NbLimbsPerBn254Element], &res.X)
	recomposeFp(limbs[emparams.NbLimbsPerBn254Element:], &res.Y)

	return res
}

// decomposeFp decomposes a big.Int into a slice of 30 bit limbs.
func decomposeFp(input *big.Int, mod *big.Int) []field.Element {
	var res [emparams.NbLimbsPerBn254Element]field.Element

	var tmp, buf big.Int
	tmp.Set(input)

	for i := 0; i < len(res); i++ {
		buf.Mod(&tmp, mod)
		res[i].SetBigInt(&buf)
		tmp.Rsh(&tmp, emparams.NbBitsPerLimb)
	}

	return res[:]
}

func convGtGnarkToWizard(elem bn254.GT) [nbGtLimbs]field.Element {
	var res [nbGtLimbs]field.Element

	var buf, mod big.Int
	mod.Lsh(big.NewInt(1), emparams.NbBitsPerLimb)

	copyTo := func(i int, b fp.Element) {
		b.BigInt(&buf)
		limbs := decomposeFp(&buf, &mod)

		start := i * emparams.NbLimbsPerBn254Element
		for j, limb := range limbs {
			res[start+j] = limb
		}
	}

	copyTo(0, elem.C0.B0.A0)
	copyTo(1, elem.C0.B0.A1)
	copyTo(2, elem.C0.B1.A0)
	copyTo(3, elem.C0.B1.A1)
	copyTo(4, elem.C0.B2.A0)
	copyTo(5, elem.C0.B2.A1)
	copyTo(6, elem.C1.B0.A0)
	copyTo(7, elem.C1.B0.A1)
	copyTo(8, elem.C1.B1.A0)
	copyTo(9, elem.C1.B1.A1)
	copyTo(10, elem.C1.B2.A0)
	copyTo(11, elem.C1.B2.A1)

	return res
}

func inputFillerMillerLoop(circuitInstance, inputIndex int) field.Element {
	// prev = 1
	// p = g1 gen
	// q = g2 gen
	// curr = e(p, q)
	tbl := []string{
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000001",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000001",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000002",
		"0x0000198e",
		"0x24e4e483",
		"0x1483a726",
		"0x02fedcc7",
		"0x3b5d25f1",
		"0x2a924ccd",
		"0x1a9e7129",
		"0x1f9216de",
		"0x2ef312c2",
		"0x00001800",
		"0x37bbc487",
		"0x31e76426",
		"0x28019979",
		"0x1c447967",
		"0x10c8b53d",
		"0x35edadd4",
		"0x1b7af573",
		"0x1992f6ed",
		"0x00000906",
		"0x22741617",
		"0x3f075ec9",
		"0x3a66b5a4",
		"0x0c3395bc",
		"0x12cc4cdc",
		"0x0b38ef35",
		"0x16b36b73",
		"0x1122975b",
		"0x000012c8",
		"0x17a976e3",
		"0x06deb4aa",
		"0x2dc60237",
		"0x0b408fe3",
		"0x3479da43",
		"0x043d37b4",
		"0x339b3005",
		"0x26fa7daa",
		"0x00001325",
		"0x013ad140",
		"0x1a5bf6b0",
		"0x1ebd5adf",
		"0x1b0fa2e4",
		"0x19b59024",
		"0x233e66e4",
		"0x32455d1a",
		"0x01ba8566",
		"0x000016ed",
		"0x3c410244",
		"0x3f3d3546",
		"0x1d8c57d7",
		"0x1158d61b",
		"0x29a9cda7",
		"0x2aac1bc4",
		"0x3c30b5ca",
		"0x3e31cee2",
		"0x0000132b",
		"0x19bd7882",
		"0x377a759f",
		"0x107c4e97",
		"0x26b0412c",
		"0x1844884b",
		"0x26365529",
		"0x3d8c3214",
		"0x192ad16f",
		"0x00000770",
		"0x303a9845",
		"0x2b198641",
		"0x107e09c9",
		"0x0368f7e6",
		"0x0b7035ad",
		"0x34c6235d",
		"0x01b3454b",
		"0x3d8981d2",
		"0x0000258c",
		"0x248e03af",
		"0x05b7819f",
		"0x10fd90e6",
		"0x0a51e1a1",
		"0x082ac70e",
		"0x1458a75d",
		"0x3d3c1c75",
		"0x269f97d1",
		"0x00002126",
		"0x21523c72",
		"0x2cec5a8e",
		"0x18813aba",
		"0x2d3b3ff3",
		"0x05e93a07",
		"0x30629d82",
		"0x23a6d8b4",
		"0x1a4e2c5e",
		"0x00000f32",
		"0x19a6765c",
		"0x0d1caa67",
		"0x159890bd",
		"0x3e890de6",
		"0x082655aa",
		"0x1456136d",
		"0x077209a2",
		"0x2bbb37ed",
		"0x00002292",
		"0x1534809d",
		"0x1bc1ceb9",
		"0x0580c455",
		"0x23e53421",
		"0x2511b0f5",
		"0x331aefb8",
		"0x274d3443",
		"0x3ff95c96",
		"0x000022a6",
		"0x181d7a3c",
		"0x04e7efd6",
		"0x0a98d0ce",
		"0x22d91d2e",
		"0x1719cccd",
		"0x0cacb933",
		"0x26abc59c",
		"0x06d99466",
		"0x00000427",
		"0x21a63005",
		"0x2ccc6a0e",
		"0x35129af5",
		"0x196c36fd",
		"0x01b94339",
		"0x1e2ed560",
		"0x17e7d81a",
		"0x288ce821",
		"0x00000b02",
		"0x2626d368",
		"0x34883f87",
		"0x0db9f3e4",
		"0x1e7ffb57",
		"0x0dcc954f",
		"0x2bd0ea9e",
		"0x25c679b5",
		"0x3ad47418",
		"0x000012f1",
		"0x0730dc45",
		"0x23663d21",
		"0x2dcadbe1",
		"0x2808cb64",
		"0x20786af7",
		"0x2d4465c6",
		"0x3857fade",
		"0x2389480b",
	}
	var res field.Element
	_, err := res.SetString(tbl[inputIndex%(nbG1Limbs+nbG2Limbs+2*nbGtLimbs)])
	if err != nil {
		utils.Panic("failed to set string: %v", err)
	}
	return res
}

func inputFillerFinalExp(circuitInstance, inputIndex int) field.Element {
	// accumulator e(-p, q)
	// inputs e(p, q)
	// result e(-p, q) * e(p, q) == 1
	tbl := []string{
		"0x00001325",
		"0x013ad140",
		"0x1a5bf6b0",
		"0x1ebd5adf",
		"0x1b0fa2e4",
		"0x19b59024",
		"0x233e66e4",
		"0x32455d1a",
		"0x01ba8566",
		"0x000016ed",
		"0x3c410244",
		"0x3f3d3546",
		"0x1d8c57d7",
		"0x1158d61b",
		"0x29a9cda7",
		"0x2aac1bc4",
		"0x3c30b5ca",
		"0x3e31cee2",
		"0x0000132b",
		"0x19bd7882",
		"0x377a759f",
		"0x107c4e97",
		"0x26b0412c",
		"0x1844884b",
		"0x26365529",
		"0x3d8c3214",
		"0x192ad16f",
		"0x00000770",
		"0x303a9845",
		"0x2b198641",
		"0x107e09c9",
		"0x0368f7e6",
		"0x0b7035ad",
		"0x34c6235d",
		"0x01b3454b",
		"0x3d8981d2",
		"0x0000258c",
		"0x248e03af",
		"0x05b7819f",
		"0x10fd90e6",
		"0x0a51e1a1",
		"0x082ac70e",
		"0x1458a75d",
		"0x3d3c1c75",
		"0x269f97d1",
		"0x00002126",
		"0x21523c72",
		"0x2cec5a8e",
		"0x18813aba",
		"0x2d3b3ff3",
		"0x05e93a07",
		"0x30629d82",
		"0x23a6d8b4",
		"0x1a4e2c5e",
		"0x00002131",
		"0x39f641f0",
		"0x0ce5f11d",
		"0x2b7e4948",
		"0x02cf4fb1",
		"0x18344eaf",
		"0x32c69566",
		"0x291026b8",
		"0x2cc1c55a",
		"0x00000dd1",
		"0x3e6837ae",
		"0x3e40cccb",
		"0x3b9615b0",
		"0x1d732975",
		"0x3b48f364",
		"0x1401b91b",
		"0x0934fc17",
		"0x1883a0b1",
		"0x00000dbd",
		"0x3b7f3e10",
		"0x151aabae",
		"0x367e0937",
		"0x1e7f4069",
		"0x0940d78c",
		"0x3a6fefa0",
		"0x09d66abf",
		"0x11a368e1",
		"0x00002c3c",
		"0x31f68846",
		"0x2d363176",
		"0x0c043f10",
		"0x27ec269a",
		"0x1ea16120",
		"0x28edd373",
		"0x189a5840",
		"0x2ff01526",
		"0x00002561",
		"0x2d75e4e3",
		"0x257a5bfd",
		"0x335ce621",
		"0x22d86240",
		"0x128e0f0a",
		"0x1b4bbe35",
		"0x0abbb6a5",
		"0x1da8892f",
		"0x00001d73",
		"0x0c6bdc06",
		"0x369c5e63",
		"0x134bfe24",
		"0x194f9232",
		"0x3fe23962",
		"0x19d8430c",
		"0x382a357c",
		"0x34f3b53c",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000001",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000002",
		"0x0000198e",
		"0x24e4e483",
		"0x1483a726",
		"0x02fedcc7",
		"0x3b5d25f1",
		"0x2a924ccd",
		"0x1a9e7129",
		"0x1f9216de",
		"0x2ef312c2",
		"0x00001800",
		"0x37bbc487",
		"0x31e76426",
		"0x28019979",
		"0x1c447967",
		"0x10c8b53d",
		"0x35edadd4",
		"0x1b7af573",
		"0x1992f6ed",
		"0x00000906",
		"0x22741617",
		"0x3f075ec9",
		"0x3a66b5a4",
		"0x0c3395bc",
		"0x12cc4cdc",
		"0x0b38ef35",
		"0x16b36b73",
		"0x1122975b",
		"0x000012c8",
		"0x17a976e3",
		"0x06deb4aa",
		"0x2dc60237",
		"0x0b408fe3",
		"0x3479da43",
		"0x043d37b4",
		"0x339b3005",
		"0x26fa7daa",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000000",
		"0x00000001",
	}
	var res field.Element
	_, err := res.SetString(tbl[inputIndex%(nbG1Limbs+nbG2Limbs+nbGtLimbs+2)])
	if err != nil {
		utils.Panic("failed to set string: %v", err)
	}
	return res
}

func inputFillerG2Membership(circuitInstance, inputIndex int) field.Element {
	// g2 generator
	tbl := []string{
		"0x0000198e",
		"0x24e4e483",
		"0x1483a726",
		"0x02fedcc7",
		"0x3b5d25f1",
		"0x2a924ccd",
		"0x1a9e7129",
		"0x1f9216de",
		"0x2ef312c2",
		"0x00001800",
		"0x37bbc487",
		"0x31e76426",
		"0x28019979",
		"0x1c447967",
		"0x10c8b53d",
		"0x35edadd4",
		"0x1b7af573",
		"0x1992f6ed",
		"0x00000906",
		"0x22741617",
		"0x3f075ec9",
		"0x3a66b5a4",
		"0x0c3395bc",
		"0x12cc4cdc",
		"0x0b38ef35",
		"0x16b36b73",
		"0x1122975b",
		"0x000012c8",
		"0x17a976e3",
		"0x06deb4aa",
		"0x2dc60237",
		"0x0b408fe3",
		"0x3479da43",
		"0x043d37b4",
		"0x339b3005",
		"0x26fa7daa",
		"0x1",
	}
	var res field.Element
	_, err := res.SetString(tbl[inputIndex%(nbG2Limbs+1)])
	if err != nil {
		utils.Panic("failed to set string: %v", err)
	}
	return res
}
