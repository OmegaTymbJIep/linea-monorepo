package ecdsa

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/linea-monorepo/prover/maths/field"
)

const ecRecoverColNumber = 9

type EcRecoverInstance struct {
	PKX [ecRecoverColNumber]frontend.Variable `gnark:",public"`
	PKY [ecRecoverColNumber]frontend.Variable `gnark:",public"`
	H   [ecRecoverColNumber]frontend.Variable `gnark:",public"`
	V   [ecRecoverColNumber]frontend.Variable `gnark:",public"`
	R   [ecRecoverColNumber]frontend.Variable `gnark:",public"`
	S   [ecRecoverColNumber]frontend.Variable `gnark:",public"`

	//PKXHi, PKXLo, PKYHi, PKYLo frontend.Variable `gnark:",public"`
	//HHi, HLo                   frontend.Variable `gnark:",public"`
	//VHi, VLo                   frontend.Variable `gnark:",public"`
	//RHi, RLo                   frontend.Variable `gnark:",public"`
	//SHi, SLo                   frontend.Variable `gnark:",public"`

	SUCCESS_BIT  frontend.Variable `gnark:",public"`
	ECRECOVERBIT frontend.Variable `gnark:",public"`
}

type MultiEcRecoverCircuit struct {
	Instances []EcRecoverInstance `gnark:",public"`
}

func newMultiEcRecoverCircuit(nbInstances int) *MultiEcRecoverCircuit {
	return &MultiEcRecoverCircuit{
		Instances: make([]EcRecoverInstance, nbInstances),
	}
}

func (c *MultiEcRecoverCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[emparams.Secp256k1Fr, sw_emulated.AffinePoint[emparams.Secp256k1Fp]](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	for i := 0; i < len(c.Instances); i++ {
		PK, msg, v, r, s, strictRange, isFailure, err := c.Instances[i].splitInputs(api)
		if err != nil {
			return fmt.Errorf("split inputs: %w", err)
		}
		recovered := evmprecompiles.ECRecover(api, *msg, v, *r, *s, strictRange, isFailure)
		curve.AssertIsEqual(PK, recovered)
	}
	return nil
}

func (c *EcRecoverInstance) splitInputs(api frontend.API) (PK *sw_emulated.AffinePoint[emparams.Secp256k1Fp], msg *emulated.Element[emparams.Secp256k1Fr], v frontend.Variable, r, s *emulated.Element[emparams.Secp256k1Fr], strictRange, isFailure frontend.Variable, err error) {
	fr, err2 := emulated.NewField[emparams.Secp256k1Fr](api)
	if err2 != nil {
		err = fmt.Errorf("field emulation: %w", err2)
		return
	}
	fp, err2 := emulated.NewField[emparams.Secp256k1Fp](api)
	if err2 != nil {
		err = fmt.Errorf("field emulation: %w", err2)
		return
	}

	// TODO: we might need to reverse slices to obtain different encoding (big endian or little endian)
	msg = fr.NewElement(c.H)

	PK = &sw_emulated.AffinePoint[emparams.Secp256k1Fp]{
		X: *fp.NewElement(c.PKX),
		Y: *fp.NewElement(c.PKY),
	}

	for i := 0; i < ecRecoverColNumber-1; i++ {
		api.AssertIsEqual(c.V[i], 0)
	}
	v = c.V[ecRecoverColNumber-1]

	r = fr.NewElement(c.R)
	s = fr.NewElement(c.S)

	isFailure = api.Sub(1, c.SUCCESS_BIT)
	strictRange = c.ECRECOVERBIT

	return
}

func inputFiller(circuitInstance, inputIndex int) field.Element {
	// every instance has 14 inputs.
	// pubkey xHi, pubkey xLo, pubkey yHi, pubkey yLo, hHi, hLo, vHi, vLo, rHi, rLo, sHi, sLo, successBit, ecrecoverBit

	// public key 1*G
	placeholderPubkey := [64]byte{0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0xe, 0x11, 0x8, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8}
	placeholderPubkeyXLimbs := to30BitLimbs(placeholderPubkey[:32])
	placeholderPubkeyYLimbs := to30BitLimbs(placeholderPubkey[32:])
	// 1000000...0000
	placeholderTxHash := [32]byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	placeholderTxHashLimbs := to30BitLimbs(placeholderTxHash[:])
	// valid signature for secret key 1 and tx hash 1 with random nonce
	// valid signature for secret key 1 and tx hash 1 with nonce 2
	placeholderSignature := [66]byte{
		// r part of signature
		0xc6, 0x4, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x9, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
		// s part of signature
		0xe3, 0x82, 0x3f, 0xca, 0x20, 0xf6, 0xbe, 0xb6, 0x98, 0x22, 0xa0, 0x37, 0x4a, 0xe0, 0x3e, 0x6b, 0x8b, 0x93, 0x35, 0x99, 0x1e, 0x1b, 0xee, 0x71, 0xb5, 0xbf, 0x34, 0x23, 0x16, 0x53, 0x70, 0x13,
		// v part of signature (in EVM format, 27 is added to the recovery id)
		0x0, 0x1b,
	}

	placeholderSignatureR := to30BitLimbs(placeholderSignature[:32])
	placeholderSignatureS := to30BitLimbs(placeholderSignature[32:64])

	var ret field.Element
	switch {
	// PK X
	case inputIndex < 9:
		ret.SetBytes(placeholderPubkeyXLimbs[inputIndex])
	// PK Y
	case inputIndex >= 9 && inputIndex < 18:
		ret.SetBytes(placeholderPubkeyYLimbs[inputIndex-9])
	// MSG
	case inputIndex >= 18 && inputIndex < 27:
		ret.SetBytes(placeholderTxHashLimbs[inputIndex-18])
	// v (0 limbs)
	case inputIndex >= 27 && inputIndex < 35:
		ret.SetUint64(0)
	// v (1b limb)
	case inputIndex == 36:
		ret.SetUint64(0x1b)
	// r
	case inputIndex >= 36 && inputIndex < 45:
		ret.SetBytes(placeholderSignatureR[inputIndex-36])
	// s
	case inputIndex >= 45 && inputIndex < 54:
		ret.SetBytes(placeholderSignatureS[inputIndex-45])
	case inputIndex == 55: // success bit
		ret.SetUint64(1)
	case inputIndex == 56: // ecrecover bit
		ret.SetUint64(0)
	}

	return ret
}
