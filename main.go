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

// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
func main() {
	config := struct {
		address      string
		debug        string
		secret       string
		clientId     string
		clientSecret string
		Issuer       string
		difficulty   int
	}{
		address:      withDefault(os.Getenv("ADDRESS"), ":4159"),
		debug:        os.Getenv("DEBUG"),
		secret:       os.Getenv("SECRET"),
		clientId:     withDefault(os.Getenv("CLIENT_ID"), "bot-idp"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		Issuer:       withDefault(os.Getenv("ISSUER"), "https://github.com/AlexanderYastrebov/bot-idp"),
		difficulty:   must(strconv.Atoi(withDefault(os.Getenv("DIFFICULTY"), "16"))),
	}

	if config.debug != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			slog.Debug("Request", "method", r.Method, "url", r.URL)
			http.NotFound(w, r)
		})
	}

	d, err := base64urld(config.secret)
	if err != nil {
		panic(err)
	}
	signingKeyPriv := ed25519.NewKeyFromSeed(d)
	signingKeyPub := signingKeyPriv.Public().(ed25519.PublicKey)

	slog.Debug("Keys", "signingKeyPub", base64url(signingKeyPub))

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "I'm OK\n")
	})
	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		openidConfiguration(w, r, config.Issuer)
	})
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request", "method", r.Method, "url", r.URL)
		r.ParseForm()
		if r.Form.Get("response_type") != "code" {
			slog.Debug("👎 response_type")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_id") != config.clientId {
			slog.Debug("👎 client_id")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		redirectUri := r.Form.Get("redirect_uri")
		ru, err := url.Parse(redirectUri)
		if err != nil {
			slog.Debug("👎 redirect_uri")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		q := ru.Query()
		q.Set("response_type", r.FormValue("code"))
		q.Set("client_id", config.clientId)
		q.Set("redirect_uri", redirectUri)
		q.Set("scope", r.FormValue("scope"))
		q.Set("state", r.FormValue("state"))
		ru.RawQuery = q.Encode()

		challenge(w, r, signingKeyPriv, config.difficulty, ru.String())
	})
	http.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request", "method", r.Method, "url", r.URL)
		r.ParseForm()
		slog.Debug("Request", "form", r.Form)
		if r.Form.Get("grant_type") != "authorization_code" {
			slog.Debug("👎 grant_type")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		clientId, clientSecret, ok := r.BasicAuth()
		slog.Debug("Request", "clientId", clientId, "clientSecret", clientSecret, "config.clientId", config.clientId)
		if clientId == "" {
			clientId, clientSecret, ok = r.FormValue("client_id"), r.FormValue("client_secret"), true
			slog.Debug("Request", "clientId", clientId, "clientSecret", clientSecret, "config.clientId", config.clientId)
		}

		if !ok {
			slog.Debug("👎 Authorization")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if clientId != config.clientId {
			slog.Debug("👎 clientId")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if clientSecret != config.clientSecret {
			slog.Debug("👎 clientSecret")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		// TODO: validate redirect_uri

		parts := strings.SplitN(r.Form.Get("code"), ".", 3)
		if len(parts) != 3 {
			slog.Debug("👎 code")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		nonceDec, hash, signature := parts[0], parts[1], parts[2]

		slog.Debug("code", "nonce", nonceDec, "hash", hash, "signature", signature)
		claims := make(map[string]any)
		if !jwtVerify(signature, signingKeyPub, &claims) {
			slog.Debug("👎 signature")
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		slog.Debug("signature", "claims", claims)
		// trust payload due to valid signature
		block, _ := base64urld(claims["block"].(string))
		nonce, err := strconv.ParseUint(nonceDec, 10, 64)
		if err != nil {
			slog.Debug("👎 nonce")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		h := sha256.New()
		h.Write(block)
		binary.Write(h, binary.BigEndian, nonce)

		if hash != hex.EncodeToString(h.Sum(nil)) {
			slog.Debug("👎 hash")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		now := time.Now().Unix()
		iat := now
		exp := now + 3600
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		respBody := fmt.Sprintf(`{
			"access_token": "SlAV32hkKG",
			"token_type": "Bearer",
			"expires_in": %d,
			"id_token": "%s"
		}`, 3600, jwtSign(fmt.Sprintf(`{
			"iss": "%s",
			"aud": "%s",
			"sub": "sss",
			"exp": %d,
			"iat": %d,
			"email": "janedoe@example.org"
		}`, config.Issuer,
			config.clientId,
			exp, iat),
			signingKeyPriv))
		slog.Debug("Response", "body", respBody)
		fmt.Fprintln(w, respBody)
	})
	http.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		respBody := fmt.Sprintf(`{
			"keys": [
				{
					"kty":"OKP",
					"crv":"Ed25519",
					"x":"%s"
				}
		]}%s`, base64url(signingKeyPub), "\n")
		slog.Debug("Response", "body", respBody)
		fmt.Fprintln(w, respBody)
	})

	slog.Info("Listen", "address", config.address)
	http.ListenAndServe(config.address, nil)
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

// https://openid.net/specs/openid-connect-discovery-1_0.html
func openidConfiguration(w http.ResponseWriter, _ *http.Request, issuer string) {
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
}%s`, issuer, issuer, issuer, issuer, "\n")
}

//go:embed challenge.js
var challengeJs string

func challenge(w http.ResponseWriter, _ *http.Request, key ed25519.PrivateKey, difficulty int, redirectUri string) {
	block := make([]byte, 32)
	rand.Read(block)

	blockHex := hex.EncodeToString(block)
	signature := jwtSign(fmt.Sprintf(`{
		"block": "%s"
	}`, base64url(block)), key)

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
		<pre id="out">⛏️ Let's solve a challenge, shall we?
		</pre>
	</body>
</html>%s`, challengeJs, blockHex, signature, difficulty, redirectUri, "\n")
}

var (
	base64url  = base64.RawURLEncoding.EncodeToString
	base64urld = base64.RawURLEncoding.DecodeString
)

// https://www.rfc-editor.org/rfc/rfc7519.txt
func jwtSign(payload string, key ed25519.PrivateKey) string {
	headerPayload := base64url([]byte(`{"typ":"JWT","alg":"EdDSA"}`)) + "." + base64url([]byte(payload))
	return headerPayload + "." + base64url(ed25519.Sign(key, []byte(headerPayload)))
}

func jwtVerify(jwt string, key ed25519.PublicKey, claims any) bool {
	if header, payloadSignature, ok := strings.Cut(jwt, "."); ok {
		payload, signature, ok := strings.Cut(payloadSignature, ".")
		if ok {
			if p, err := base64urld(payload); err == nil {
				if s, err := base64urld(signature); err == nil {
					if ed25519.Verify(key, []byte(header+"."+payload), s) {
						return (json.Unmarshal(p, claims) == nil)
					}
				}
			}
		}
	}
	return false
}
