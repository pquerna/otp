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

	"image"
	"net/url"
	"strings"
)

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
	return ""
}

func (k *Key) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}
