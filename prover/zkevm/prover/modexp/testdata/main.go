package main

import (
	"fmt"
	"io"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/linea-monorepo/prover/backend/files"
)

func main() {
	writeDir := "./"

	for _, tcase := range testCases {
		// Generate the input CSV file
		f := files.MustOverwrite(writeDir + tcase.name + "_input.csv")
		dumpAsCsv(f, tcase.tab)
		f.Close()

		// Generate the module CSV file
		f = files.MustOverwrite(writeDir + tcase.name + "_module.csv")
		dumpModuleAsCsv(f, tcase.tab, !tcase.large)
		f.Close()
	}
}

var testCases = []struct {
	name  string
	tab   [][]*big.Int
	large bool
}{
	{
		name:  "single_256_bits",
		large: false,
		tab: func() [][]*big.Int {

			var (
				tab  = make([][]*big.Int, 5)
				rng  = rand.New(rand.NewSource(42))
				inst = createRandomModexp(rng, false)
			)

			pushModexpToInput(inst, tab)
			return tab
		}(),
	},
	{
		name:  "single_4096_bits",
		large: true,
		tab: func() [][]*big.Int {

			var (
				tab  = make([][]*big.Int, 5)
				rng  = rand.New(rand.NewSource(43))
				inst = createRandomModexp(rng, true)
			)

			pushModexpToInput(inst, tab)
			return tab
		}(),
	},
}

func createRandomModexp(rng *rand.Rand, large bool) [4]*big.Int {

	var (
		maxValue = emparams.Mod1e256{}.Modulus()
		res      = [4]*big.Int{}
	)

	if large {
		maxValue = emparams.Mod1e4096{}.Modulus()
	}

	res[0] = new(big.Int).Rand(rng, maxValue)
	res[1] = new(big.Int).Rand(rng, maxValue)
	res[2] = new(big.Int).Rand(rng, maxValue)
	res[3] = new(big.Int).Exp(res[0], res[1], res[2])

	return res
}

func dumpAsCsv(w io.Writer, tab [][]*big.Int) {

	fmt.Fprintf(w, "LIMBS,IS_MODEXP_BASE,IS_MODEXP_EXPONENT,IS_MODEXP_MODULUS,IS_MODEXP_RESULT\n")

	for i := range tab[0] {
		hexStr := fmt.Sprintf("0x%08x", tab[0][i])
		fmt.Fprintf(w, "%v,%v,%v,%v,%v\n", hexStr, tab[1][i].String(), tab[2][i].String(), tab[3][i].String(), tab[4][i].String())
	}
}

func dumpModuleAsCsv(w io.Writer, tab [][]*big.Int, isSmall bool) {
	fmt.Fprintf(w, "MODEXP_LIMBS,MODEXP_IS_ACTIVE,MODEXP_IS_SMALL,MODEXP_IS_LARGE,MODEXP_TO_SMALL_CIRC\n")

	for i := range tab[0] {
		hexStr := fmt.Sprintf("0x%08x", tab[0][i])
		isNonZero := tab[0][i].Sign() > 0
		toSmallCirc := 0

		if isSmall && isNonZero {
			toSmallCirc = 1
		}

		isSmallValue := 0
		isLargeValue := 0
		if isSmall {
			isSmallValue = 1
		} else {
			isLargeValue = 1
		}

		fmt.Fprintf(w, "%v,%v,%v,%v,%v\n",
			hexStr, 1, isSmallValue, isLargeValue, toSmallCirc)
	}
}

func pushModexpToInput(inst [4]*big.Int, tab [][]*big.Int) {

	var (
		limbs = splitInto30BitLimbs(inst[0])
		zero  = &big.Int{}
		one   = big.NewInt(1)
	)

	for i := range limbs {
		tab[0] = append(tab[0], limbs[i])
		tab[1] = append(tab[1], one)
		tab[2] = append(tab[2], zero)
		tab[3] = append(tab[3], zero)
		tab[4] = append(tab[4], zero)
	}

	limbs = splitInto30BitLimbs(inst[1])

	for i := range limbs {
		tab[0] = append(tab[0], limbs[i])
		tab[1] = append(tab[1], zero)
		tab[2] = append(tab[2], one)
		tab[3] = append(tab[3], zero)
		tab[4] = append(tab[4], zero)
	}

	limbs = splitInto30BitLimbs(inst[2])

	for i := range limbs {
		tab[0] = append(tab[0], limbs[i])
		tab[1] = append(tab[1], zero)
		tab[2] = append(tab[2], zero)
		tab[3] = append(tab[3], one)
		tab[4] = append(tab[4], zero)
	}

	limbs = splitInto30BitLimbs(inst[3])

	for i := range limbs {
		tab[0] = append(tab[0], limbs[i])
		tab[1] = append(tab[1], zero)
		tab[2] = append(tab[2], zero)
		tab[3] = append(tab[3], zero)
		tab[4] = append(tab[4], one)
	}
}

// splitInto30BitLimbs splits a big integer into limbs of 30 bits each
// Returns limbs in big-endian order (most significant limb first)
func splitInto30BitLimbs(x *big.Int) [137]*big.Int {
	var (
		res       = [137]*big.Int{}
		mask      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 30), big.NewInt(1)) // 2^30 - 1
		xCopy     = new(big.Int).Set(x)
		bitCount  = x.BitLen()
		limbCount = (bitCount + 29) / 30 // Ceiling of bitCount/30
		limbs     = make([]*big.Int, 0, limbCount)
	)

	if x.Sign() == 0 {
		for i := 0; i < 137; i++ {
			res[i] = big.NewInt(0)
		}
		return res
	}

	for xCopy.Sign() > 0 {
		limb := new(big.Int).And(xCopy, mask)
		limbs = append(limbs, limb)
		xCopy.Rsh(xCopy, 30)
	}

	for i := 0; i < len(limbs)/2; i++ {
		limbs[i], limbs[len(limbs)-1-i] = limbs[len(limbs)-1-i], limbs[i]
	}

	offset := 137 - len(limbs)
	for i := 0; i < offset; i++ {
		res[i] = big.NewInt(0)
	}

	for i := 0; i < len(limbs); i++ {
		res[i+offset] = limbs[i]
	}

	return res
}
