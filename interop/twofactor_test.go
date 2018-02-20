/**
 *  Copyright 2018 Paul Querna
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

package interop_test

import (
	"testing"
	"time"

	"github.com/gokyle/twofactor"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestTwoFactor(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Algorithm:   otp.AlgorithmSHA512,
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	tf, label, err := twofactor.FromURL(key.URL())
	require.NoError(t, err)
	require.NotNil(t, tf)
	require.Equal(t, "Example.com:alice@example.com", label)

	code := tf.OTP()
	require.NotEmpty(t, code)

	valid, err := totp.ValidateCustom(code, key.Secret(),
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA512,
		},
	)
	require.NoError(t, err)
	require.True(t, valid)
}
