package otp_test

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func ExampleNewKeyFromURL() {
	// Reload the URL saved from key.URL() during enrollment.
	storedURL := "otpauth://totp/Example.com:alice@example.com?secret=NBSWY3DPEB3W64TMMQ&issuer=Example.com&period=60&digits=8&algorithm=SHA256"
	key, err := otp.NewKeyFromURL(storedURL)
	if err != nil {
		panic(err)
	}
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}

	fmt.Println(key.Issuer(), key.AccountName())
	fmt.Println(key.Secret())
	fmt.Println(key.Period(), key.Digits(), key.Algorithm())
	fmt.Println(img.Bounds())
	// Output:
	// Example.com alice@example.com
	// NBSWY3DPEB3W64TMMQ
	// 60 8 SHA256
	// (0,0)-(200,200)
}

func ExampleKey_Secret() {
	// Reload the Base32 secret saved from key.Secret() during enrollment.
	storedSecret := "nbswy3dpeb3w64tmmq"
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(storedSecret))
	if err != nil {
		panic(err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      secret,
		Period:      60,
		Digits:      otp.DigitsEight,
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(key.Secret())
	fmt.Println(key.Period(), key.Digits(), key.Algorithm())
	// Output:
	// NBSWY3DPEB3W64TMMQ
	// 60 8 SHA256
}
