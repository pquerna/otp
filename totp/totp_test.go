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

// TODO: http://tools.ietf.org/html/rfc6238#appendix-B

func TestValidateRFCMatrix(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	valid, err := ValidateCustom("94287082", secret, time.Unix(59, 0).UTC(),
		ValidateOpts{
			Period: 30,
			Digits: DigitsEight,
		})
	require.NoError(t, err, "test matrix is expected to succeed")
	require.True(t, valid, "test matrix is expected to succeed")

	valid, err = ValidateCustom("07081804", secret, time.Unix(1111111109, 0).UTC(),
		ValidateOpts{
			Period: 30,
			Digits: DigitsEight,
		})
	require.NoError(t, err, "test matrix is expected to succeed")
	require.True(t, valid, "test matrix is expected to succeed")
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
