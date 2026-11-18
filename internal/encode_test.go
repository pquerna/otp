package internal

import (
	"net/url"
	"reflect"
	"testing"
)

func TestEncodeQueryRoundTrip(t *testing.T) {
	values := url.Values{
		"R&D + key": {"first&value=1", "second+value %20"},
		"empty":     {""},
		"unused":    nil,
	}
	encoded := EncodeQuery(values)
	decoded, err := url.ParseQuery(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"R&D + key": values["R&D + key"], "empty": {""}}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded query = %#v, want %#v", decoded, want)
	}
}

func TestEncodeQueryPreservesSpaceEncoding(t *testing.T) {
	if got := EncodeQuery(url.Values{"issuer": {"Snake Oil"}, "secret": {"ABC"}}); got != "issuer=Snake%20Oil&secret=ABC" {
		t.Fatalf("unexpected encoding: %s", got)
	}
	if EncodeQuery(nil) != "" || EncodeQuery(url.Values{}) != "" {
		t.Fatal("empty values must produce an empty query")
	}
}
