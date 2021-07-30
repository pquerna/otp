package totp

import (
	"crypto/rand"

	"github.com/pquerna/otp"
)

func (opts *GenerateOpts) defaults() error {
	if opts.Issuer == "" {
		return otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return otp.ErrGenerateMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
	}

	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}

	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}

	return nil
}

//
func (opts *ValidateOpts) defaultOpts() {
	if opts.Skew == 0 {
		opts.Skew = 1
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Period == 0 {
		opts.Period = 30
	}
}
