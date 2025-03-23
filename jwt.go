package main

import "encoding/base64"

// https://www.rfc-editor.org/rfc/rfc7519.txt
func jwtEncode(header, payload string) string {
	b := base64.RawURLEncoding.AppendEncode(nil, []byte(header))
	b = append(b, '.')
	b = base64.RawStdEncoding.AppendEncode(b, []byte(payload))
	b = append(b, '.')
	b = append(b, jwtSign(header, payload)...)
	return string(b)
}

func jwtSign(header, payload string) string {
	return ""
}
