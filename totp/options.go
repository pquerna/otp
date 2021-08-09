package totp

import (
	"io"
	"time"

	"github.com/pquerna/otp"
)

// GenerateOpts generate opts are the options to be used in
// generate and validate functions
type GenerateOpt func(opts *GenerateOpts)

func WithIssuer(issuer string) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.Issuer = issuer
	}
}

func WithAccountName(account string) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.AccountName = account
	}
}

func WithGenPeriod(period uint) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.Period = period
	}
}
func WithSecret(secret []byte) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.Secret = secret
	}
}

func WithGenDigits(digits otp.Digits) GenerateOpt {

	return func(opts *GenerateOpts) {
		opts.Digits = digits
	}
}

func WithGenAlgorithm(algo otp.Algorithm) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.Algorithm = algo
	}
}

func WithRandomGenerator(r io.Reader) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.Rand = r
	}
}

func WithSecretSize(size uint) GenerateOpt {
	return func(opts *GenerateOpts) {
		opts.SecretSize = size
	}
}

//
type ValidateOpt func(opt *ValidateOpts)

func WithPeriod(period uint) ValidateOpt {
	return func(opt *ValidateOpts) {
		opt.Period = period
	}
}
func WithSkew(skew uint) ValidateOpt {
	return func(opt *ValidateOpts) {
		opt.Skew = skew
	}
}

func WithDigits(digits otp.Digits) ValidateOpt {
	return func(opt *ValidateOpts) {
		opt.Digits = digits
	}
}

func WithAlgorithm(algo otp.Algorithm) ValidateOpt {
	return func(opt *ValidateOpts) {
		opt.Algorithm = algo
	}
}

func WithTime(t time.Time) ValidateOpt {
	return func(opt *ValidateOpts) {
		opt.t = t
	}
}
