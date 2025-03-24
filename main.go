package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	address      string
	debug        string
	secret       string
	clientId     string
	clientSecret string
	issuer       string
	difficulty   int

	signingKeyPriv ed25519.PrivateKey
	signingKeyPub  ed25519.PublicKey
}

// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
func main() {
	config := &config{
		address:      withDefault(os.Getenv("ADDRESS"), ":4159"),
		debug:        os.Getenv("DEBUG"),
		secret:       os.Getenv("SECRET"),
		clientId:     withDefault(os.Getenv("CLIENT_ID"), "bot-idp"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		issuer:       withDefault(os.Getenv("ISSUER"), "https://github.com/AlexanderYastrebov/bot-idp"),
		difficulty:   must(strconv.Atoi(withDefault(os.Getenv("DIFFICULTY"), "16"))),
	}

	if config.debug != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			slog.Debug("Request", "method", r.Method, "url", r.URL)
			http.NotFound(w, r)
		})
	}

	config.signingKeyPriv = ed25519.NewKeyFromSeed(must(base64DecodeString(config.secret)))
	config.signingKeyPub = config.signingKeyPriv.Public().(ed25519.PublicKey)

	slog.Debug("Keys", "config.signingKeyPub", base64url(config.signingKeyPub))

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "I'm OK") })
	http.HandleFunc("/.well-known/openid-configuration", config.openidConfigurationHandler)
	http.HandleFunc("/authorize", config.authorizeHandler)
	http.HandleFunc("POST /token", config.tokenHandler)
	http.HandleFunc("GET /keys", config.keysHandler)

	slog.Info("Listen", "address", config.address)
	http.ListenAndServe(config.address, nil)
}

// https://openid.net/specs/openid-connect-discovery-1_0.html
func (config *config) openidConfigurationHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, `{
  "issuer": "%s",
  "authorization_endpoint": "%s/authorize",
  "token_endpoint": "%s/token",
  "jwks_uri": "%s/keys",
  "scopes_supported": [
    "openid"
  ],
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "EdDSA"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "ui_locales_supported": [
    "en"
  ],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": false
}%s`, config.issuer, config.issuer, config.issuer, config.issuer, "\n")
}

func (config *config) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	badRequest := func(msg string) {
		slog.Debug(msg)
		http.Error(w, msg, http.StatusBadRequest)
	}

	r.ParseForm()
	slog.Debug("Request", "endpoint", "authorize", "method", r.Method, "url", r.URL, "form", r.Form)

	if r.Form.Get("response_type") != "code" {
		badRequest("👎 response_type")
		return
	}

	if r.Form.Get("client_id") != config.clientId {
		badRequest("👎 client_id")
		return
	}

	redirectUri := r.Form.Get("redirect_uri")
	ru, err := url.Parse(redirectUri)
	if err != nil {
		badRequest("👎 redirect_uri")
		return
	}

	q := ru.Query()
	q.Set("response_type", r.FormValue("code"))
	q.Set("client_id", config.clientId)
	q.Set("redirect_uri", redirectUri)
	q.Set("scope", r.FormValue("scope"))
	q.Set("state", r.FormValue("state"))
	ru.RawQuery = q.Encode()

	challenge(w, r, config.signingKeyPriv, config.difficulty, ru.String())
}

//go:embed challenge.js
var challengeJs string

func challenge(w http.ResponseWriter, _ *http.Request, key ed25519.PrivateKey, difficulty int, redirectUri string) {
	block := make([]byte, 32)
	rand.Read(block)

	// challenge is short-lived
	expiresIn := int64(10)
	iat := time.Now().Unix()
	exp := iat + expiresIn

	blockHex := hex.EncodeToString(block)
	signature := jwtSign(fmt.Sprintf(`{
		"exp": %d,
		"block": "%s"
	}`, exp, base64url(block)), key)

	fmt.Fprintf(w, `<!doctype html>
<html lang=en>
	<head>
		<meta charset="utf-8">
		<title>Welcome</title>
		<script>%s</script>
		<script>
			(async() => {
				const log = (msg)=>{
					const out = document.getElementById("out");
					out.innerHTML = out.innerHTML.trimEnd() + "\n" + msg;
				};
				await challenge({blockHex: "%s", signature: "%s", difficulty: %d, redirectUri: "%s", log: log});
			})();
		</script>
	</head>
	<body>
		<pre id="out">⛏️ Let's solve a challenge, shall we?</pre>
	</body>
</html>%s`, challengeJs, blockHex, signature, difficulty, redirectUri, "\n")
}

func (config *config) tokenHandler(w http.ResponseWriter, r *http.Request) {
	unauthorized := func(msg string) {
		slog.Debug(msg)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	r.ParseForm()
	slog.Debug("Request", "form", r.Form)

	if r.Form.Get("grant_type") != "authorization_code" {
		unauthorized("👎 grant_type")
		return
	}

	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientId, clientSecret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	slog.Debug("Request", "clientId", clientId, "clientSecret", clientSecret)

	if clientId != config.clientId {
		unauthorized("👎 clientId")
		return
	}
	if clientSecret != config.clientSecret {
		unauthorized("👎 clientSecret")
		return
	}
	// TODO: validate redirect_uri

	parts := strings.SplitN(r.Form.Get("code"), ".", 3)
	if len(parts) != 3 {
		unauthorized("👎 code")
		return
	}
	nonceDec, hash, signature := parts[0], parts[1], parts[2]

	slog.Debug("code", "nonce", nonceDec, "hash", hash, "signature", signature)

	claims := make(map[string]any)
	if !jwtVerify(signature, config.signingKeyPub, claims) {
		unauthorized("👎 signature")
		return
	}
	slog.Debug("signature", "claims", claims)

	// trust payload due to valid signature
	block, _ := base64urld(claims["block"].(string))
	nonce, err := strconv.ParseUint(nonceDec, 10, 64)
	if err != nil {
		unauthorized("👎 nonce")
		return
	}

	h := sha256.New()
	h.Write(block)
	binary.Write(h, binary.BigEndian, nonce)

	if hash != hex.EncodeToString(h.Sum(nil)) {
		unauthorized("👎 hash")
		return
	}

	expiresIn := int64(10)
	iat := time.Now().Unix()
	exp := iat + expiresIn

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	respBody := fmt.Sprintf(`{
		"access_token": "SlAV32hkKG",
		"token_type": "Bearer",
		"expires_in": %d,
		"id_token": "%s"
	}`, expiresIn, jwtSign(fmt.Sprintf(`{
		"iss": "%s",
		"aud": "%s",
		"sub": "sss",
		"exp": %d,
		"iat": %d,
		"email": "janedoe@example.org"
	}`, config.issuer,
		config.clientId,
		exp, iat),
		config.signingKeyPriv))
	slog.Debug("Response", "body", respBody)
	fmt.Fprintln(w, respBody)
}

func (config *config) keysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	respBody := fmt.Sprintf(`{
			"keys": [
				{
					"kty":"OKP",
					"crv":"Ed25519",
					"x":"%s"
				}
		]}%s`, base64url(config.signingKeyPub), "\n")
	slog.Debug("Response", "body", respBody)
	fmt.Fprintln(w, respBody)
}

// https://www.rfc-editor.org/rfc/rfc7519.txt
func jwtSign(payload string, key ed25519.PrivateKey) string {
	headerPayload := base64url([]byte(`{"typ":"JWT","alg":"EdDSA"}`)) + "." + base64url([]byte(payload))
	return headerPayload + "." + base64url(ed25519.Sign(key, []byte(headerPayload)))
}

func jwtVerify(jwt string, key ed25519.PublicKey, claims map[string]any) bool {
	if header, payloadSignature, ok := strings.Cut(jwt, "."); ok {
		payload, signature, ok := strings.Cut(payloadSignature, ".")
		if ok {
			if p, err := base64urld(payload); err == nil {
				if s, err := base64urld(signature); err == nil {
					if ed25519.Verify(key, []byte(header+"."+payload), s) {
						if json.Unmarshal(p, &claims) == nil {
							if expv, ok := claims["exp"]; ok {
								if expn, ok := expv.(float64); ok {
									return time.Now().Before(time.Unix(int64(expn), 0))
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}

var (
	base64url  = base64.RawURLEncoding.EncodeToString
	base64urld = base64.RawURLEncoding.DecodeString
)

// base64DecodeString detects base64 variant and decodes s.
// See [base64.RawURLEncoding]
func base64DecodeString(s string) ([]byte, error) {
	enc := base64.URLEncoding
	if strings.ContainsAny(s, "+/") {
		enc = base64.StdEncoding
	}
	if !strings.ContainsAny(s, "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	return enc.DecodeString(s)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func withDefault[T comparable](val, def T) T {
	var zero T
	if val == zero {
		return def
	}
	return val
}
