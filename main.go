package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
)

// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
func main() {
	config := struct {
		address      string
		debug        string
		clientId     string
		clientSecret string
	}{
		address:      withDefault(os.Getenv("ADDRESS"), ":4159"),
		debug:        os.Getenv("DEBUG"),
		clientId:     withDefault(os.Getenv("CLIENT_ID"), "bot-idp"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "I'm OK\n")
	})

	if config.debug != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			slog.Debug("Request", "method", r.Method, "url", r.URL)
			http.NotFound(w, r)
		})
	}

	http.HandleFunc("/.well-known/openid-configuration", openidConfiguration)
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request", "method", r.Method, "url", r.URL)
		// https://server.example.com/authorize?
		// response_type=code
		// &client_id=s6BhdRkqt3
		// &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
		// &scope=openid%20profile
		// &state=af0ifjsldkj
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
		q.Set("code", "XXX")
		ru.RawQuery = q.Encode()

		http.Redirect(w, r, ru.String(), http.StatusFound)
	})
	http.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request", "method", r.Method, "url", r.URL)
		// POST /token HTTP/1.1
		// Host: server.example.com
		// Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
		// Content-Type: application/x-www-form-urlencoded

		// grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
		//   &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
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
		// TODO: validate code, redirect_uri

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{
			"access_token":"SlAV32hkKG",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
			"id_token": "qqq"
		}`+"\n")
	})
	slog.Info("Listen", "address", config.address)
	http.ListenAndServe(config.address, nil)
}

func withDefault[T comparable](val, def T) T {
	var zero T
	if val == zero {
		return def
	}
	return val
}

// https://openid.net/specs/openid-connect-discovery-1_0.html
func openidConfiguration(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
{
  "issuer": "http://localhost:9998/",
  "authorization_endpoint": "http://localhost:9998/authorize",
  "token_endpoint": "http://localhost:9998/token",
  "jwks_uri": "http://localhost:9998/keys",
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
    "Ed25519"
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
}`+"\n")
}
