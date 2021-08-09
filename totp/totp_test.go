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
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"encoding/base32"
	"testing"
	"time"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

//
// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
// 		http://www.rfc-editor.org/errata_search.php?rfc=6238
// this only took a few hours of head/desk interaction to figure out.
//
func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{61, "94287082", otp.AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
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
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "generate larger TOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  13, // anything that is not divisable by 5, really
	})
	require.NoError(t, err, "Secret size is valid when length not divisable by 5.")
	require.NotContains(t, k.Secret(), "=", "Secret has no escaped characters.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err, "Secret generation failed")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Secret wa not valid base32")
	require.Equal(t, sec, []byte("helloworld"), "Specified Secret was not kept")
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", sec)

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n)
	require.NoError(t, err)

	valid := Validate(code, w.Secret())
	require.True(t, valid)
}
