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

package otp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyAllThere(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "totp", k.Type(), "Extracting Type")
	require.Equal(t, "Example", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, "JBSWY3DPEHPK3PXP", k.Secret(), "Extracting Secret")
	require.Equal(t, AlgorithmSHA256, k.Algorithm())
	require.Equal(t, DigitsEight, k.Digits())
}

func TestKeyIssuerOnlyInPath(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "Example", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
}

func TestKeyNoIssuer(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
}

func TestKeyWithNewLine(t *testing.T) {
	w, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP
`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "JBSWY3DPEHPK3PXP", sec)
}
