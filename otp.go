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
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"

	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"image"
	"net/url"
	"strings"
)

// Error when attempting to convert the secret from base32 to raw bytes.
var ErrValidateSecretInvalidBase32 = errors.New("Decoding of secret as base32 failed.")

// The user provided passcode was not 6 characters as expected.
var ErrValidateInputInvalidLength6 = errors.New("Input was not 6 characters")

// The user provided passcode was not 8 characters as expected.
var ErrValidateInputInvalidLength8 = errors.New("Input was not 8 characters")

// When generating a Key, the Issuer must be set.
var ErrGenerateMissingIssuer = errors.New("Issuer must be set")

// When generating a Key, the Account Name must be set.
var ErrGenerateMissingAccountName = errors.New("AccountName must be set")

// Key represents an TOTP or HTOP key.
type Key struct {
	orig string
	url  *url.URL
}

func NewKeyFromURL(orig string) (*Key, error) {
	u, err := url.Parse(orig)

	if err != nil {
		return nil, err
	}

	return &Key{
		orig: orig,
		url:  u,
	}, nil
}

func (k *Key) String() string {
	return k.orig
}

func (k *Key) Image(width int, height int) (image.Image, error) {
	b, err := qr.Encode(k.orig, qr.M, qr.Auto)

	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, width, height)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (k *Key) Type() string {
	return k.url.Host
}

func (k *Key) Issuer() string {
	q := k.url.Query()

	issuer := q.Get("issuer")

	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

func (k *Key) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

func (k *Key) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}

type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}

type Digits int

const (
	DigitsSix Digits = iota
	DigitsEight
)

func (d Digits) Format(in int32) string {
	switch d {
	case DigitsSix:
		return fmt.Sprintf("%06d", in)
	case DigitsEight:
		return fmt.Sprintf("%08d", in)
	}
	panic("unreached")
}

func (d Digits) Legnth() int {
	switch d {
	case DigitsSix:
		return 6
	case DigitsEight:
		return 8
	}
	panic("unreached")
}

func (d Digits) String() string {
	switch d {
	case DigitsSix:
		return "6"
	case DigitsEight:
		return "8"
	}
	panic("unreached")
}
