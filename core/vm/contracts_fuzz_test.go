// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func FuzzPrecompiledContracts(f *testing.F) {
	// Create list of addresses
	var addrs []common.Address
	for k := range allPrecompiles {
		addrs = append(addrs, k)
	}
	f.Fuzz(func(t *testing.T, addr uint8, input []byte) {
		a := addrs[int(addr)%len(addrs)]
		p := allPrecompiles[a]

		// Bind inputs for the ecrecover precompile
		if a == common.BytesToAddress([]byte{1}) {
			input = BindEcRecoverInput(input)
		}

		// Bind inputs for the modexp precompile
		if a == common.BytesToAddress([]byte{5}) {
			input = BindModExpInput(input)
		}

		// Bind inputs for the ecAdd precompile
		if a == common.BytesToAddress([]byte{6}) {
			input = BindEcAddInput(input)
		}

		// Bind inputs for the ecMul precompile
		if a == common.BytesToAddress([]byte{7}) {
			input = BindEcMulInput(input)
		}

		// Bind inputs for the blake2f precompile
		if a == common.BytesToAddress([]byte{9}) {
			input = BindBlake2FInput(input)
		}

		if a == common.BytesToAddress([]byte{100}) {
			input = BindTmHeaderValidateInput(input)
		}

		if a == common.BytesToAddress([]byte{101}) {
			input = BindIavlMerkleProofValidatePlatoInput(input)
		}

		if a == common.BytesToAddress([]byte{102}) {
			input = BindBlsSignatureVerifyInput(input)
		}

		if a == common.BytesToAddress([]byte{103}) {
			input = BindCometBFTLightBlockValidateHertzInput(input)
		}

		if a == common.BytesToAddress([]byte{105}) {
			input = BindSecp256k1SignatureVerifyInput(input)
		}

		gas := p.RequiredGas(input)
		if gas > 10_000_000 {
			return
		}
		inWant := string(input)
		RunPrecompiledContract(p, input, gas)
		if inHave := string(input); inWant != inHave {
			t.Errorf("Precompiled %v modified input data", a)
		}
	})
}
