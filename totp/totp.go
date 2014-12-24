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
	"errors"
	"github.com/pquerna/otp"
)

type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

type GenerateOptions struct {
	Issuer      string
	AccountName string
	Algorithm   Algorithm
}

func Generate(opts *GenerateOptions) (*otp.Key, error) {
	// url encode the Issuer/AccountName

	// otp.NewKeyFromURL()
	return nil, errors.New("dead")
}
