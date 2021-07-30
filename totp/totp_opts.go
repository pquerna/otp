package totp

import (
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// ValidateWithOpts validate with opts
// it has deprecated Validate and will replace it soon.
func ValidateWithOpts(passcode, secret string, validateOpts ...ValidateOpt) (bool, error) {
	return validateCustomOpt(passcode, secret, time.Now(), validateOpts...)
}

// validateCustomOpt validates a TOTP given a user specified time and custom options.
// Most users should use Validate() to provide an interpolatable TOTP experience.
// This replicates ValidateCustomOpt
func validateCustomOpt(passcode, secret string, t time.Time, validateOpts ...ValidateOpt) (bool, error) {

	opts := new(ValidateOpts)

	for _, opt := range validateOpts {
		opt(opts)
	}
	opts.defaultOpts()

	counters := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	counters = append(counters, uint64(counter))
	for i := 1; i <= int(opts.Skew); i++ {
		counters = append(counters, uint64(counter+int64(i)))
		counters = append(counters, uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		rv, err := hotp.ValidateCustom(passcode, counter, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if rv {
			return true, nil
		}
	}

	return false, nil
}

//

// GenerateWithOpts a new TOTP Key.
func GenerateWithOpts(genOpts ...GenerateOpt) (*otp.Key, error) {

	opts := new(GenerateOpts)

	for _, opt := range genOpts {
		opt(opts)
	}

	if err := opts.defaults(); err != nil {
		return nil, err
	}
	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	v := url.Values{}

	if opts.Secret != nil {
		v.Set("secret", b32NoPadding.EncodeToString(opts.Secret))
	} else {
		secret := make([]byte, opts.SecretSize)
		_, err := opts.Rand.Read(secret)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32NoPadding.EncodeToString(secret))
	}

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

// GenerateCodeWithOpts takes a timepoint and produces a passcode using a
// secret and the provided opts. (Under the hood, this is making an adapted
// call to hotp.GenerateCodeCustom)
func GenerateCodeWithOpts(secret string, t time.Time, validateOpts ...ValidateOpt) (passcode string, err error) {

	opts := new(ValidateOpts)

	for _, opt := range validateOpts {
		opt(opts)
	}
	opts.defaultOpts()

	counter := uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))
	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})
	if err != nil {
		return "", err
	}
	return passcode, nil
}
