package internal

import (
	"net/url"
	"sort"
	"strings"
)

// EncodeQuery is a copy-paste of url.Values.Encode, except it uses %20 instead
// of + to encode spaces. This is necessary to correctly render spaces in some
// authenticator apps, like Google Authenticator.
func EncodeQuery(v url.Values) string {
	if v == nil {
		return ""
	}
	var buf strings.Builder

	// Google Authenticator expects the secret to be first, so handle it separately
	keys := make([]string, 0, len(v))
	keys = append(keys, "secret")
	for k := range v {
		if k != "secret" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys[1:])
	for _, k := range keys {
		vs := v[k]
		keyEscaped := url.PathEscape(k) // changed from url.QueryEscape
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.PathEscape(v)) // changed from url.QueryEscape
		}
	}
	return buf.String()
}
