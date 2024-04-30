package vm

import (
	"math/big"
	"math/rand"
)

func BindEcRecoverInput(input []byte) []byte {
	// Length of input data ecrecover expects
	const ecRecoverInputLength = 128

	// Maximum value of a private key in ethereum
	var secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

	// Pad input to 128 bytes
	input = padInput(input, ecRecoverInputLength)

	// Obtain the v,r,s values from input data
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// Bind inputs within min/max bounds
	// value = MIN_VALUE + (value % (MAX_VALUE - MIN_VALUE));
	v = v % 1
	r = r.Mod(r, secp256k1N)
	s = s.Mod(s, secp256k1N)

	// Reconstruct and return input
	boundedInput := make([]byte, ecRecoverInputLength)
	boundedInput[63] = v + 27
	copy(boundedInput[64:96], r.Bytes())
	copy(boundedInput[96:128], s.Bytes())

	return boundedInput
}

func BindModExpInput(input []byte) []byte {
	// Length of input data modexp expects
	const modexpInputLength = 96

	// Pad input to 96 bytes
	input = padInput(input, modexpInputLength)

	// Obtain the exponent, modulus, and base from input data
	exponent := new(big.Int).SetBytes(input[:32])
	modulus := new(big.Int).SetBytes(input[32:64])
	base := new(big.Int).SetBytes(input[64:96])

	// Bind inputs within min/max bounds
	// value = MIN_VALUE + (value % (MAX_VALUE - MIN_VALUE));
	exponent = exponent.Mod(exponent, modulus)
	base = base.Mod(base, modulus)

	// Reconstruct and return input
	boundedInput := make([]byte, modexpInputLength)
	copy(boundedInput[:32], exponent.Bytes())
	copy(boundedInput[32:64], modulus.Bytes())
	copy(boundedInput[64:96], base.Bytes())

	return boundedInput
}

func BindEcAddInput(input []byte) []byte {
	// Length of input data ecAdd expects
	const ecAddInputLength = 64

	// Pad input to 64 bytes
	input = padInput(input, ecAddInputLength)

	return input
}

func BindEcMulInput(input []byte) []byte {
	// Length of input data ecMul expects
	const ecMulInputLength = 64

	// Pad input to 64 bytes
	input = padInput(input, ecMulInputLength)

	return input
}

func BindBlake2FInput(input []byte) []byte {
	// Minimum length of input data blake2f expects
	const blake2fMinInputLength = 213

	// pad input to 119 bytes
	input = padInput(input, blake2fMinInputLength)

	// Ensure final byte is valid (byte(0 or 1))
	if input[212] != byte(0) && input[212] != byte(1) {
		// Set final byte to byte(0 or 1)
		input[212] = input[212] % 1
	}

	return input
}

func BindTmHeaderValidateInput(input []byte) []byte {
	// Minimum length of input data tmHeaderValidate expects
	const tmHeaderValidateInputLength = 32

	// Pad input to 32 bytes
	input = padInput(input, tmHeaderValidateInputLength)

	return input
}

func BindIavlMerkleProofValidatePlatoInput(input []byte) []byte {
	const iavlMerkleProofValidatePlatoInputLength = 32

	// Pad input to 32 bytes
	input = padInput(input, iavlMerkleProofValidatePlatoInputLength)

	return input
}

func BindCometBFTLightBlockValidateHertzInput(input []byte) []byte {
	const cometBFTLightBlockValidateHertzInputLength = 32

	// Pad input to 32 bytes
	input = padInput(input, cometBFTLightBlockValidateHertzInputLength)

	return input
}

func BindBlsSignatureVerifyInput(input []byte) []byte {
	const blsSignatureVerifyInputLength = 96

	// Pad input to 96 bytes
	input = padInput(input, blsSignatureVerifyInputLength)

	return input
}

func BindSecp256k1SignatureVerifyInput(input []byte) []byte {
	const secp256k1SignatureVerifyInputLength = int(secp256k1PubKeyLength) + int(secp256k1SignatureLength) + int(secp256k1SignatureMsgHashLength)

	// Pad input
	input = padInput(input, secp256k1SignatureVerifyInputLength)

	return input
}

func padInput(input []byte, inputLength int) []byte {
	if len(input) < inputLength {
		// Create new input
		newInput := make([]byte, inputLength)
		copy(newInput, input)

		// Fill in the rest of the input
		for i := len(input); i < inputLength; i++ {
			newInput[i] = byte(rand.Intn(255))
		}

		return newInput
	}

	return input
}
