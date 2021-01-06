package main

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"bufio"
	"bytes"
	"fmt"
	"image/png"
	"io/ioutil"
	"os"
	"time"
)

func display(key *otp.Key, data []byte) {
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Println("Writing PNG to qr-code.png....")
	ioutil.WriteFile("qr-code.png", data, 0644)
	fmt.Println("")
	fmt.Println("Please add your TOTP to your OTP Application now!")
	fmt.Println("")
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}


// Generates Passcode using a UTF-8 (not base32) secret and custom paramters
func GeneratePassCode(secret string) string{
        passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
                Period:    30,
                Skew:      1,
                Digits:    otp.DigitsSix,
                Algorithm: otp.AlgorithmSHA1,
        })
        if err != nil {
                panic(err)
        }
        return passcode
}

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	})
	if err != nil {
		panic(err)
	}
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// display the QR code to the user.
	display(key, buf.Bytes())

	// Generate temporary passcode
	generateTempPasscode := os.Getenv("GENERATE_TEMP_PASSCODE")
	if generateTempPasscode == "true" {
		fmt.Println("Generating temporary passcode, valid for 30 seconds...")
		tempPasscode := GeneratePassCode(key.Secret())
		fmt.Printf("Temp Passcode: %s\n", tempPasscode)
	}

	// Now Validate that the user's successfully added the passcode.
	fmt.Println("Validating TOTP...")
	passcode := promptForPasscode()
	valid := totp.Validate(passcode, key.Secret())
	if valid {
		println("Valid passcode!")
		os.Exit(0)
	} else {
		println("Invalid passcode!")
		os.Exit(1)
	}
}
