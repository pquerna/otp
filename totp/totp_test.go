/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package totp

import (
	"encoding/base32"
	"github.com/stretchr/testify/require"

	"testing"
	"time"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   Algorithm
	Secret string
}

//
// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
// 		http://www.rfc-editor.org/errata_search.php?rfc=6238
// this only took a few hours of head/desk interaction to figure out.
//
func TestValidateRFCMatrix(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	tests := []tc{
		tc{59, "94287082", AlgorithmSHA1, secSha1},
		tc{59, "46119246", AlgorithmSHA256, secSha256},
		tc{59, "90693936", AlgorithmSHA512, secSha512},
		tc{1111111109, "07081804", AlgorithmSHA1, secSha1},
		tc{1111111109, "68084774", AlgorithmSHA256, secSha256},
		tc{1111111109, "25091201", AlgorithmSHA512, secSha512},
		tc{1111111111, "14050471", AlgorithmSHA1, secSha1},
		tc{1111111111, "67062674", AlgorithmSHA256, secSha256},
		tc{1111111111, "99943326", AlgorithmSHA512, secSha512},
		tc{1234567890, "89005924", AlgorithmSHA1, secSha1},
		tc{1234567890, "91819424", AlgorithmSHA256, secSha256},
		tc{1234567890, "93441116", AlgorithmSHA512, secSha512},
		tc{2000000000, "69279037", AlgorithmSHA1, secSha1},
		tc{2000000000, "90698825", AlgorithmSHA256, secSha256},
		tc{2000000000, "38618901", AlgorithmSHA512, secSha512},
		tc{20000000000, "65353130", AlgorithmSHA1, secSha1},
		tc{20000000000, "77737706", AlgorithmSHA256, secSha256},
		tc{20000000000, "47863826", AlgorithmSHA512, secSha512},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    DigitsEight,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic TOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 16, len(k.Secret()), "Secret is 16 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "generate larger TOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")
}
