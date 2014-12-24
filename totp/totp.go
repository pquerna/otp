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

	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const debug = false

// Validates that input is a valid TOTP given
// the current time. A shortcut for ValidateCustom.
func Validate(input string, secret string) bool {
	rv, _ := ValidateCustom(
		input,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		},
	)
	return rv
}

type ValidateOpts struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Periods before or affter the current time to allow.  Value of 1 allows up to Period
	// of either side of the specified time.  Defaults to 0 allowed skews.
	Skew uint
	// Digits as part of the input. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

var ValidateSecretInvalidBase32 = errors.New("Decoding of secret as base32 failed.")
var ValidateInputInvalidLength6 = errors.New("TOTP Input was not 6 characters")
var ValidateInputInvalidLength8 = errors.New("TOTP Input was not 8 characters")

func ValidateCustom(input string, secret string, t time.Time, opts ValidateOpts) (bool, error) {
	input = strings.TrimSpace(input)

	switch opts.Digits {
	case DigitsSix:
		if len(input) != 6 {
			return false, ValidateInputInvalidLength6
		}
	case DigitsEight:
		if len(input) != 8 {
			return false, ValidateInputInvalidLength8
		}
	}

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return false, ValidateSecretInvalidBase32
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	counters := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	counters = append(counters, uint64(counter))
	for i := 1; i <= int(opts.Skew); i++ {
		counters = append(counters, uint64(counter+int64(i)))
		counters = append(counters, uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		// TODO: refactor
		buf := make([]byte, 8)
		mac := hmac.New(opts.Algorithm.Hash, secretBytes)
		binary.BigEndian.PutUint64(buf, counter)
		if debug {
			fmt.Printf("counter=%v\n", counter)
			fmt.Printf("buf=%v\n", buf)
		}

		mac.Write(buf)
		sum := mac.Sum(nil)

		// "Dynamic truncation" in RFC 4226
		// http://tools.ietf.org/html/rfc4226#section-5.4
		offset := sum[len(sum)-1] & 0xf
		value := int64(((int(sum[offset]) & 0x7f) << 24) |
			((int(sum[offset+1] & 0xff)) << 16) |
			((int(sum[offset+2] & 0xff)) << 8) |
			(int(sum[offset+3]) & 0xff))

		l := opts.Digits.Legnth()
		mod := int32(value % int64(math.Pow10(l)))

		if debug {
			fmt.Printf("offset=%v\n", offset)
			fmt.Printf("value=%v\n", value)
			fmt.Printf("mod'ed=%v\n", mod)
		}

		otpstr := opts.Digits.Format(mod)
		if otpstr == input {
			return true, nil
		}
	}

	return false, nil
}

// Options for .Generate()
type GenerateOpts struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Size in size of the generated Secret. Defaults to 10 bytes.
	SecretSize uint
	// Digits to request. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

var GenerateMissingIssuer = errors.New("Issuer must be set")
var GenerateMissingAccountName = errors.New("AccountName must be set")

// Generates a new TOTP Key.
func Generate(opts GenerateOpts) (*otp.Key, error) {
	// url encode the Issuer/AccountName
	if opts.Issuer == "" {
		return nil, GenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, GenerateMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 10
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	v := url.Values{}
	secret := make([]byte, opts.SecretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}

	v.Set("secret", base32.StdEncoding.EncodeToString(secret))
	v.Set("issuer", opts.Issuer)
	v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: v.Encode(),
	}

	return otp.NewKeyFromURL(u.String())
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
