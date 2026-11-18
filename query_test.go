package otp_test

import (
	"bytes"
	"encoding/base32"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateQueryRoundTrip(t *testing.T) {
	secret := []byte("12345678901234567890")
	wantSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	for _, kind := range []string{"hotp", "totp"} {
		for _, issuer := range []string{"Example", "Snake Oil", "R&D", "A+B", "Ops/West?x=1#tag%", "R&D + Co=EU%20", "日本の会社"} {
			t.Run(kind+"/"+issuer, func(t *testing.T) {
				// Exercise the enrollment APIs with a deterministic random reader,
				// then import the resulting URL as an authenticator would.
				var key *otp.Key
				var err error
				if kind == "hotp" {
					key, err = hotp.Generate(hotp.GenerateOpts{
						Issuer: issuer, AccountName: "alice+ops@example.com",
						Algorithm: otp.AlgorithmSHA256, Digits: otp.DigitsEight,
						SecretSize: uint(len(secret)), Rand: bytes.NewReader(secret),
					})
				} else {
					key, err = totp.Generate(totp.GenerateOpts{
						Issuer: issuer, AccountName: "alice+ops@example.com",
						Algorithm: otp.AlgorithmSHA256, Digits: otp.DigitsEight, Period: 45,
						SecretSize: uint(len(secret)), Rand: bytes.NewReader(secret),
					})
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, encoded := range []string{key.String(), key.URL()} {
					parsed, err := url.Parse(encoded)
					if err != nil {
						t.Fatal(err)
					}
					query, err := url.ParseQuery(parsed.RawQuery)
					if err != nil {
						t.Fatal(err)
					}
					want := url.Values{"algorithm": {"SHA256"}, "digits": {"8"}, "issuer": {issuer}, "secret": {wantSecret}}
					if kind == "totp" {
						want.Set("period", "45")
					}
					if !reflect.DeepEqual(query, want) {
						t.Fatalf("imported query = %#v, want %#v", query, want)
					}
					if strings.Contains(parsed.RawQuery, "+") {
						t.Fatalf("query contains a literal plus instead of percent escapes: %s", parsed.RawQuery)
					}
					imported, err := otp.NewKeyFromURL(encoded)
					if err != nil {
						t.Fatal(err)
					}
					if imported.Issuer() != issuer || imported.Secret() != wantSecret || imported.AccountName() != "alice+ops@example.com" || imported.Type() != kind || imported.Algorithm() != otp.AlgorithmSHA256 || imported.Digits() != otp.DigitsEight {
						t.Fatalf("import changed enrollment data: %s", encoded)
					}
					if strings.Contains(issuer, " ") && !strings.Contains(parsed.RawQuery, "%20") {
						t.Fatalf("space is not encoded as %%20: %s", parsed.RawQuery)
					}
				}
			})
		}
	}
}
