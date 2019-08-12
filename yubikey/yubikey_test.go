package yubikey

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	passcode = "tkfncciivrgcbbihneijknvhcudrhletcghgghvdrfcj"
	secret = "5f2e977c19f9f463b542e7077a4131ed"
	counter = uint64(0)
)

func TestValidator_Validate(t *testing.T) {
	v := Validator{
		Passcode:passcode,
		Secret:secret,
		Counter:counter,
	}
	valid := v.Validate()
	require.True(t, valid)
}